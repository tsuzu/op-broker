package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The local agent is the ssh-agent pattern applied to broker tickets: a
// per-user daemon holds grant tickets in memory only, and
// `opbroker read` / `opbroker status` fetch them over a Unix socket at a
// well-known path when $BROKER_TICKET is not set. Shells and agent tools
// (Codex etc.) therefore never see, pass around, or persist the ticket:
// they just run `opbroker read`, and the ticket travels only over the
// local socket. The socket lives in a 0700 directory, so only processes
// running as the same uid can talk to the daemon.
//
// The daemon holds MULTIPLE tickets at once (one per grant, keyed by
// ticket hash), so parallel tools with different scopes do not evict
// each other; `resolve` picks the entry whose scopes cover the
// requested reference. Entries drop out as their grants expire, and the
// daemon exits after 10 minutes holding nothing.

func agentDir() (string, error) {
	if d := os.Getenv("OPBROKER_AGENT_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "opbroker"), nil
}

func agentSockPath() (string, error) {
	if p := os.Getenv("OPBROKER_AGENT_SOCK"); p != "" {
		return p, nil
	}
	d, err := agentDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "agent.sock"), nil
}

type agentReq struct {
	Op          string   `json:"op"`
	Ticket      string   `json:"ticket,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Ref         string   `json:"ref,omitempty"`
	ExpiresUnix int64    `json:"expires_unix,omitempty"`
}

type agentEntryInfo struct {
	Scopes      []string `json:"scopes"`
	ExpiresUnix int64    `json:"expires_unix"`
}

type agentResp struct {
	OK      bool             `json:"ok"`
	Ticket  string           `json:"ticket,omitempty"`
	Tickets []string         `json:"tickets,omitempty"`
	Entries []agentEntryInfo `json:"entries,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// ---- daemon ----

type agentEntry struct {
	ticket    string
	scopes    []string
	expiresAt time.Time
}

type agentState struct {
	mu         sync.Mutex
	entries    map[string]*agentEntry // ticketHash -> entry
	emptySince time.Time              // when the daemon last stopped holding anything
}

// pruneLocked drops expired entries. Caller holds s.mu.
func (s *agentState) pruneLocked(now time.Time) {
	for h, e := range s.entries {
		if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
			delete(s.entries, h)
		}
	}
	if len(s.entries) == 0 && s.emptySince.IsZero() {
		s.emptySince = now
	}
	if len(s.entries) > 0 {
		s.emptySince = time.Time{}
	}
}

// bestLocked returns the entry covering ref (or the latest-expiring
// entry when ref is ""), pruning expired entries first.
func (s *agentState) bestLocked(ref string) (*agentEntry, bool) {
	s.pruneLocked(time.Now())
	var best *agentEntry
	for _, e := range s.entries {
		if ref != "" && !scopeMatches(e.scopes, ref) {
			continue
		}
		if best == nil || e.expiresAt.After(best.expiresAt) {
			best = e
		}
	}
	return best, best != nil
}

type agentServer struct {
	ln    net.Listener
	st    *agentState
	done  chan struct{}
	once  sync.Once
	sockP string
}

func (a *agentServer) stop() {
	a.once.Do(func() {
		close(a.done)
		a.ln.Close()
		os.Remove(a.sockP)
	})
}

func runAgentAt(sockPath string) error {
	if conn, err := net.DialTimeout("unix", sockPath, 500*time.Millisecond); err == nil {
		conn.Close()
		return fmt.Errorf("agent already running on %s", sockPath)
	}
	os.Remove(sockPath) // stale socket
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	os.Chmod(sockPath, 0600)
	a := &agentServer{ln: ln, st: &agentState{entries: map[string]*agentEntry{}, emptySince: time.Now()}, done: make(chan struct{}), sockP: sockPath}
	go a.janitor()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-a.done:
				return nil
			default:
				return err
			}
		}
		go a.handle(conn)
	}
}

// janitor drops expired entries and exits the daemon after 10 idle
// minutes with nothing held.
func (a *agentServer) janitor() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case now := <-t.C:
			a.st.mu.Lock()
			a.st.pruneLocked(now)
			empty := len(a.st.entries) == 0
			since := a.st.emptySince
			a.st.mu.Unlock()
			if empty && !since.IsZero() && now.Sub(since) > 10*time.Minute {
				a.stop()
				return
			}
		}
	}
}

func (a *agentServer) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req agentReq
	if err := json.Unmarshal(line, &req); err != nil {
		writeAgentResp(conn, agentResp{Error: "bad request"})
		return
	}
	switch req.Op {
	case "store":
		exp := time.Time{}
		if req.ExpiresUnix > 0 {
			exp = time.Unix(req.ExpiresUnix, 0)
		}
		a.st.mu.Lock()
		a.st.entries[ticketHash(req.Ticket)] = &agentEntry{ticket: req.Ticket, scopes: req.Scopes, expiresAt: exp}
		a.st.pruneLocked(time.Now())
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: true})
	case "resolve", "get":
		a.st.mu.Lock()
		e, ok := a.st.bestLocked(req.Ref)
		a.st.mu.Unlock()
		if !ok {
			writeAgentResp(conn, agentResp{Error: "no ticket held"})
			return
		}
		writeAgentResp(conn, agentResp{OK: true, Ticket: e.ticket})
	case "tickets":
		a.st.mu.Lock()
		a.st.pruneLocked(time.Now())
		var tickets []string
		for _, e := range a.st.entries {
			tickets = append(tickets, e.ticket)
		}
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: true, Tickets: tickets})
	case "list":
		a.st.mu.Lock()
		a.st.pruneLocked(time.Now())
		infos := []agentEntryInfo{}
		for _, e := range a.st.entries {
			var eu int64
			if !e.expiresAt.IsZero() {
				eu = e.expiresAt.Unix()
			}
			infos = append(infos, agentEntryInfo{Scopes: e.scopes, ExpiresUnix: eu})
		}
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: true, Entries: infos})
	case "present":
		a.st.mu.Lock()
		a.st.pruneLocked(time.Now())
		ok := len(a.st.entries) > 0
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: ok})
	case "forget":
		a.st.mu.Lock()
		if req.Ref != "" {
			for h, e := range a.st.entries {
				if scopeMatches(e.scopes, req.Ref) {
					delete(a.st.entries, h)
				}
			}
		} else {
			a.st.entries = map[string]*agentEntry{}
		}
		a.st.pruneLocked(time.Now())
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: true})
	case "shutdown":
		writeAgentResp(conn, agentResp{OK: true})
		go func() {
			time.Sleep(100 * time.Millisecond)
			a.stop()
		}()
	default:
		writeAgentResp(conn, agentResp{Error: "unknown op"})
	}
}

func writeAgentResp(conn net.Conn, resp agentResp) {
	b, _ := json.Marshal(resp)
	conn.Write(append(b, '\n'))
}

func runAgent() error {
	dir, err := agentDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	os.Chmod(dir, 0700)
	sock, err := agentSockPath()
	if err != nil {
		return err
	}
	return runAgentAt(sock)
}

// ---- client side ----

func agentCall(req agentReq) (*agentResp, error) {
	sock, err := agentSockPath()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp agentResp
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func agentRunning() bool {
	conn, err := func() (net.Conn, error) {
		sock, err := agentSockPath()
		if err != nil {
			return nil, err
		}
		return net.DialTimeout("unix", sock, 500*time.Millisecond)
	}()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ensureAgent starts the daemon detached (same binary, `agent` command)
// if it is not already running, and waits until its socket answers.
func ensureAgent() error {
	if agentRunning() {
		return nil
	}
	dir, err := agentDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "agent")
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if agentRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("local agent did not start; see %s", filepath.Join(dir, "agent.log"))
}

func storeToAgent(ticket string, scopes []string, expiresAt time.Time) error {
	if err := ensureAgent(); err != nil {
		return err
	}
	var eu int64
	if !expiresAt.IsZero() {
		eu = expiresAt.Unix()
	}
	resp, err := agentCall(agentReq{Op: "store", Ticket: ticket, Scopes: scopes, ExpiresUnix: eu})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent store failed: %s", resp.Error)
	}
	return nil
}

// agentResolve returns the agent-held ticket whose grant covers ref
// (or the latest-expiring ticket when ref is ""), or "".
func agentResolve(ref string) string {
	resp, err := agentCall(agentReq{Op: "resolve", Ref: ref})
	if err != nil || !resp.OK {
		return ""
	}
	return resp.Ticket
}

// agentTicket returns a ticket held by the local agent, or "".
func agentTicket() string {
	return agentResolve("")
}

// agentTickets returns all unexpired tickets the agent holds.
func agentTickets() []string {
	resp, err := agentCall(agentReq{Op: "tickets"})
	if err != nil || !resp.OK {
		return nil
	}
	return resp.Tickets
}

// agentList returns metadata (scopes + expiry) for held grants.
func agentList() []agentEntryInfo {
	resp, err := agentCall(agentReq{Op: "list"})
	if err != nil || !resp.OK {
		return nil
	}
	return resp.Entries
}

// resolveTicket is the ticket lookup when no specific reference is at
// hand (status): the explicit environment wins; otherwise the local
// agent is asked for its latest-expiring ticket.
func resolveTicket() string {
	if t := os.Getenv("BROKER_TICKET"); t != "" {
		return t
	}
	return agentTicket()
}

// resolveTicketForRef is the ticket lookup for read/describe: the
// environment wins; otherwise the agent picks the grant whose scopes
// cover ref.
func resolveTicketForRef(ref string) (ticket string, fromAgent bool) {
	if t := os.Getenv("BROKER_TICKET"); t != "" {
		return t, false
	}
	t := agentResolve(ref)
	return t, t != ""
}

// cmdAgent runs the daemon in the foreground; --stop shuts it down,
// --forget drops held tickets, --list shows held grants (metadata only).
func cmdAgent(args []string) error {
	for _, a := range args {
		if a == "--stop" {
			resp, err := agentCall(agentReq{Op: "shutdown"})
			if err != nil {
				return fmt.Errorf("no agent running: %w", err)
			}
			if !resp.OK {
				return fmt.Errorf("shutdown failed: %s", resp.Error)
			}
			fmt.Println("agent stopped")
			return nil
		}
		if a == "--forget" {
			resp, err := agentCall(agentReq{Op: "forget"})
			if err != nil {
				return fmt.Errorf("no agent running: %w", err)
			}
			if !resp.OK {
				return fmt.Errorf("forget failed: %s", resp.Error)
			}
			fmt.Println("tickets forgotten")
			return nil
		}
		if a == "--list" {
			infos := agentList()
			if len(infos) == 0 {
				fmt.Println("no tickets held")
				return nil
			}
			for _, in := range infos {
				exp := "no expiry"
				if in.ExpiresUnix > 0 {
					exp = "expires " + time.Unix(in.ExpiresUnix, 0).Format("2006-01-02 15:04:05")
				}
				fmt.Printf("scopes: %s (%s)\n", strings.Join(in.Scopes, ", "), exp)
			}
			return nil
		}
	}
	return runAgent()
}
