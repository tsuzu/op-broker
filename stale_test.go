package main

import (
	"strings"
	"testing"
	"time"
)

// After a broker restart the server forgets every ticket (RAM-only
// state), but the agent still holds them until their nominal expiry.
// status used to die on the first such entry with "404 unknown
// ticket" even though other held grants were fine, and read could
// pick a forgotten ticket. Stale entries must be dropped on sight.

func setupRealGrant(t *testing.T) (base string, s *server, realTicket string) {
	t.Helper()
	base, s = newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	startTestAgent(t)
	t.Setenv("BROKER_TICKET", "")
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go autoApprove(admin, base, s, stop)
	if err := cmdRequest([]string{"--server", base, "--agent", "--wait", "30s", "op://Automation"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	tickets := agentTickets()
	if len(tickets) != 1 {
		t.Fatalf("held tickets = %d, want 1", len(tickets))
	}
	return base, s, tickets[0]
}

func TestStatusDropsStaleEntries(t *testing.T) {
	base, _, _ := setupRealGrant(t)
	if err := storeToAgent("stale-ticket", []string{"op://Automation"}, time.Now().Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	text, live := agentStatusReport(base)
	if live != 1 {
		t.Fatalf("live = %d, want 1\n%s", live, text)
	}
	if !strings.Contains(text, "grant_expires_at") {
		t.Fatalf("report lacks the real grant:\n%s", text)
	}
	if !strings.Contains(text, "unknown ticket") {
		t.Fatalf("report lacks the stale note:\n%s", text)
	}
	if n := len(agentTickets()); n != 1 {
		t.Fatalf("held tickets after report = %d, want 1 (stale dropped)", n)
	}
}

func TestReadResolutionSkipsStaleEntry(t *testing.T) {
	base, _, real := setupRealGrant(t)
	// The stale entry has a LATER expiry, so a naive resolve picks it
	// first — the liveness probe must drop it and fall through.
	if err := storeToAgent("stale-ticket", []string{"op://Automation"}, time.Now().Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := resolveLiveTicket(base, "op://Automation/demo/api-key")
	if got != real {
		t.Fatalf("resolveLiveTicket = %q, want the real ticket", got)
	}
	if n := len(agentTickets()); n != 1 {
		t.Fatalf("held tickets = %d, want 1 (stale dropped)", n)
	}
	if code, val := doRead(base, got, "op://Automation/demo/api-key"); code != 200 || val != "demo-api-key-12345" {
		t.Fatalf("read with resolved ticket = %d %q", code, val)
	}
}
