package main

import (
	"path/filepath"
	"testing"
	"time"
)

// startTestAgent runs a daemon on a temp socket and points the client
// helpers at it via the OPBROKER_AGENT_SOCK override.
func startTestAgent(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	t.Setenv("OPBROKER_AGENT_SOCK", sock)
	go runAgentAt(sock)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if agentRunning() {
			return sock
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("test agent did not start")
	return ""
}

func TestAgentStoreGetForget(t *testing.T) {
	startTestAgent(t)
	if got := agentTicket(); got != "" {
		t.Fatalf("expected no ticket initially, got %q", got)
	}
	exp := time.Now().Add(time.Hour)
	if err := storeToAgent("ticket-abc", []string{"op://Vault"}, exp); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := agentTicket(); got != "ticket-abc" {
		t.Fatalf("agentTicket = %q, want ticket-abc", got)
	}
	// Re-storing the SAME ticket replaces its entry (e.g. after renew).
	if err := storeToAgent("ticket-abc", []string{"op://Vault", "op://Other"}, exp); err != nil {
		t.Fatalf("store 2: %v", err)
	}
	if n := len(agentTickets()); n != 1 {
		t.Fatalf("entries after same-ticket re-store = %d, want 1", n)
	}
	resp, err := agentCall(agentReq{Op: "forget"})
	if err != nil || !resp.OK {
		t.Fatalf("forget: resp=%+v err=%v", resp, err)
	}
	if got := agentTicket(); got != "" {
		t.Fatalf("expected no ticket after forget, got %q", got)
	}
}

func TestAgentMultipleGrantsResolveByScope(t *testing.T) {
	startTestAgent(t)
	long := time.Now().Add(2 * time.Hour)
	short := time.Now().Add(time.Hour)
	if err := storeToAgent("ticket-milldea", []string{"op://milldea"}, long); err != nil {
		t.Fatal(err)
	}
	if err := storeToAgent("ticket-other", []string{"op://OtherVault"}, short); err != nil {
		t.Fatal(err)
	}
	if n := len(agentTickets()); n != 2 {
		t.Fatalf("held tickets = %d, want 2", n)
	}
	if got := agentResolve("op://milldea/SMMR stg/?attribute=otp"); got != "ticket-milldea" {
		t.Fatalf("resolve milldea ref = %q", got)
	}
	if got := agentResolve("op://OtherVault/Item/field"); got != "ticket-other" {
		t.Fatalf("resolve other ref = %q", got)
	}
	if got := agentResolve("op://Unrelated/Item/field"); got != "" {
		t.Fatalf("resolve unrelated ref = %q, want empty", got)
	}
	// No ref: the latest-expiring entry wins.
	if got := agentTicket(); got != "ticket-milldea" {
		t.Fatalf("agentTicket = %q, want ticket-milldea (latest expiry)", got)
	}
	if n := len(agentList()); n != 2 {
		t.Fatalf("agentList = %d entries, want 2", n)
	}
	// Forgetting by scope drops only the covering entries.
	if _, err := agentCall(agentReq{Op: "forget", Ref: "op://milldea/SMMR stg/?attribute=otp"}); err != nil {
		t.Fatal(err)
	}
	if got := agentResolve("op://milldea"); got != "" {
		t.Fatalf("milldea entry survived scoped forget: %q", got)
	}
	if got := agentResolve("op://OtherVault/Item/field"); got != "ticket-other" {
		t.Fatalf("other entry lost by scoped forget: %q", got)
	}
}

func TestAgentExpiredTicketDropped(t *testing.T) {
	startTestAgent(t)
	if err := storeToAgent("ticket-old", []string{"op://Vault"}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := agentTicket(); got != "" {
		t.Fatalf("expired ticket was returned: %q", got)
	}
	resp, err := agentCall(agentReq{Op: "present"})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	if resp.OK {
		t.Fatal("present reported true for an expired ticket")
	}
}

func TestResolveTicketEnvWins(t *testing.T) {
	t.Setenv("BROKER_TICKET", "env-ticket")
	// No agent is running (socket path points nowhere), env must win.
	t.Setenv("OPBROKER_AGENT_SOCK", filepath.Join(t.TempDir(), "none.sock"))
	if got := resolveTicket(); got != "env-ticket" {
		t.Fatalf("resolveTicket = %q, want env-ticket", got)
	}
}

func TestResolveTicketFallsBackToAgent(t *testing.T) {
	startTestAgent(t)
	t.Setenv("BROKER_TICKET", "")
	if err := storeToAgent("agent-ticket", []string{"op://Vault"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := resolveTicket(); got != "agent-ticket" {
		t.Fatalf("resolveTicket = %q, want agent-ticket", got)
	}
}
