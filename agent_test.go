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
	if err := storeToAgent("ticket-abc", exp); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := agentTicket(); got != "ticket-abc" {
		t.Fatalf("agentTicket = %q, want ticket-abc", got)
	}
	// A second store replaces the first (latest grant wins).
	if err := storeToAgent("ticket-def", exp); err != nil {
		t.Fatalf("store 2: %v", err)
	}
	if got := agentTicket(); got != "ticket-def" {
		t.Fatalf("agentTicket after replace = %q, want ticket-def", got)
	}
	resp, err := agentCall(agentReq{Op: "forget"})
	if err != nil || !resp.OK {
		t.Fatalf("forget: resp=%+v err=%v", resp, err)
	}
	if got := agentTicket(); got != "" {
		t.Fatalf("expected no ticket after forget, got %q", got)
	}
}

func TestAgentExpiredTicketDropped(t *testing.T) {
	startTestAgent(t)
	if err := storeToAgent("ticket-old", time.Now().Add(-time.Minute)); err != nil {
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
	if err := storeToAgent("agent-ticket", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := resolveTicket(); got != "agent-ticket" {
		t.Fatalf("resolveTicket = %q, want agent-ticket", got)
	}
}
