package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// The local agent is the ssh-agent pattern applied to broker tickets: a
// per-user daemon holds the current grant's ticket in memory only, and
// `opbroker read` / `opbroker status` fetch it over a Unix socket at a
// well-known path when $BROKER_TICKET is not set. Shells and agent tools
// (Codex etc.) therefore never see, pass around, or persist the ticket:
// they just run `opbroker read`, and the ticket travels only over the
// local socket. The socket lives in a 0700 directory, so only processes
// running as the same uid can talk to the daemon.
//
// The daemon drops the ticket when the grant expires and exits after
// 10 minutes with no ticket held.

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
	Op          string `json:"op"`
	Ticket      string `json:"ticket,omitempty"`
	ExpiresUnix int64  `json:"expires_unix,omitempty"`
}

type agentResp struct {
	OK          bool   `json:"ok"`
	Ticket      string `json:"ticket,omitempty"`
	ExpiresUnix int64  `json:"expires_unix,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ---- daemon ----

type agentState struct {
	mu         sync.Mutex
	ticket     string
	expiresAt  time.Time
	emptySince time.Time // when the daemon last stopped holding a ticket
}

func (s *agentState) validTicketLocked() (string, time.Time, bool) {
	if s.ticket == "" {
		return "", time.Time{}, false
	}
	if !s.expiresAt.IsZero() && time.Now().After(s.expiresAt) {
		s.ticket = ""
		s.emptySince = time.Now()
		return "", time.Time{}, false
	}
	return s.ticket, s.expiresAt, true
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
	a := &agentServer{ln: ln, st: &agentState{emptySince: time.Now()}, done: make(chan struct{}), sockP: sockPath}
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

// janitor drops expired tickets and exits the daemon after 10 idle
// minutes with no ticket held.
func (a *agentServer) janitor() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case now := <-t.C:
			a.st.mu.Lock()
			a.st.validTicketLocked()
			empty := a.st.ticket == ""
			since := a.st.emptySince
			a.st.mu.Unlock()
			if empty && now.Sub(since) > 10*time.Minute {
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
		a.st.ticket = req.Ticket
		a.st.expiresAt = exp
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: true, ExpiresUnix: req.ExpiresUnix})
	case "get":
		a.st.mu.Lock()
		ticket, exp, ok := a.st.validTicketLocked()
		a.st.mu.Unlock()
		if !ok {
			writeAgentResp(conn, agentResp{Error: "no ticket held"})
			return
		}
		var eu int64
		if !exp.IsZero() {
			eu = exp.Unix()
		}
		writeAgentResp(conn, agentResp{OK: true, Ticket: ticket, ExpiresUnix: eu})
	case "present":
		a.st.mu.Lock()
		_, _, ok := a.st.validTicketLocked()
		a.st.mu.Unlock()
		writeAgentResp(conn, agentResp{OK: ok})
	case "forget":
		a.st.mu.Lock()
		a.st.ticket = ""
		a.st.expiresAt = time.Time{}
		a.st.emptySince = time.Now()
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

func storeToAgent(ticket string, expiresAt time.Time) error {
	if err := ensureAgent(); err != nil {
		return err
	}
	var eu int64
	if !expiresAt.IsZero() {
		eu = expiresAt.Unix()
	}
	resp, err := agentCall(agentReq{Op: "store", Ticket: ticket, ExpiresUnix: eu})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent store failed: %s", resp.Error)
	}
	return nil
}

// agentTicket returns the ticket held by the local agent, or "".
func agentTicket() string {
	resp, err := agentCall(agentReq{Op: "get"})
	if err != nil || !resp.OK {
		return ""
	}
	return resp.Ticket
}

// resolveTicket is the ticket lookup for read/status: the explicit
// environment wins; otherwise the local agent is asked.
func resolveTicket() string {
	if t := os.Getenv("BROKER_TICKET"); t != "" {
		return t
	}
	return agentTicket()
}

// cmdAgent runs the daemon in the foreground, or stops it with --stop.
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
			fmt.Println("ticket forgotten")
			return nil
		}
	}
	return runAgent()
}
