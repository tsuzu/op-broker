package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGrantCoversAll(t *testing.T) {
	cases := []struct {
		held, want []string
		ok         bool
	}{
		{[]string{"op://milldea"}, []string{"op://milldea"}, true},
		{[]string{"op://milldea"}, []string{"op://milldea/SMMR prod/one-time password?attribute=otp"}, true},
		{[]string{"op://milldea"}, []string{"op://milldea", "op://milldea/SMMR stg"}, true},
		{[]string{"op://milldea"}, []string{"op://other"}, false},
		{[]string{"op://Vault/Item"}, []string{"op://Vault"}, false},
		{[]string{"op://A", "op://B"}, []string{"op://A/x", "op://B/y"}, true},
		{[]string{"op://A"}, []string{"op://A/x", "op://B/y"}, false},
	}
	for _, c := range cases {
		if got := grantCoversAll(c.held, c.want); got != c.ok {
			t.Errorf("grantCoversAll(%v, %v) = %v, want %v", c.held, c.want, got, c.ok)
		}
	}
}

func getCSRF(c *http.Client, base string) (string, error) {
	resp, err := c.Get(base + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	const marker = `name="csrf" value="`
	i := strings.Index(string(body), marker)
	if i < 0 {
		return "", io.ErrUnexpectedEOF
	}
	rest := string(body)[i+len(marker):]
	return rest[:strings.Index(rest, `"`)], nil
}

// autoApprove approves pending requests (with a 2h TTL) until stopped.
func autoApprove(c *http.Client, base string, s *server, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		s.mu.Lock()
		var ids []string
		for _, r := range s.requests {
			if r.Status == stPending {
				ids = append(ids, r.ID)
			}
		}
		s.mu.Unlock()
		for _, id := range ids {
			csrf, err := getCSRF(c, base)
			if err != nil {
				continue
			}
			resp, err := c.PostForm(base+"/approve", url.Values{
				"csrf": {csrf}, "request_id": {id}, "ttl_seconds": {"7200"}, "max_reads": {"100"},
			})
			if err == nil {
				resp.Body.Close()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func requestCount(s *server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func TestRequestReusesExistingGrant(t *testing.T) {
	base, s := newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	startTestAgent(t)
	stop := make(chan struct{})
	defer close(stop)
	go autoApprove(admin, base, s, stop)

	args := []string{"--server", base, "--agent", "--wait", "30s", "op://Automation"}
	if err := cmdRequest(args); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if n := requestCount(s); n != 1 {
		t.Fatalf("requests after first = %d, want 1", n)
	}
	// Same scopes again: the held grant (2h) covers them with >1h
	// left, so no new request is created and the call succeeds.
	if err := cmdRequest(args); err != nil {
		t.Fatalf("second request: %v", err)
	}
	if n := requestCount(s); n != 1 {
		t.Fatalf("requests after duplicate = %d, want 1 (reuse)", n)
	}
	// A scope the held grant does not cover creates a real request.
	args2 := []string{"--server", base, "--agent", "--wait", "30s", "op://OtherVault"}
	if err := cmdRequest(args2); err != nil {
		t.Fatalf("uncovered request: %v", err)
	}
	if n := requestCount(s); n != 2 {
		t.Fatalf("requests after uncovered = %d, want 2", n)
	}
	// A held entry with <1h left is NOT reused, even when it covers.
	if err := storeToAgent("short-ticket", []string{"op://Short"}, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	args3 := []string{"--server", base, "--agent", "--wait", "30s", "op://Short"}
	if err := cmdRequest(args3); err != nil {
		t.Fatalf("short-remaining request: %v", err)
	}
	if n := requestCount(s); n != 3 {
		t.Fatalf("requests after short-remaining = %d, want 3", n)
	}
	// --min-remaining 0 disables reuse entirely.
	args4 := []string{"--server", base, "--agent", "--wait", "30s", "--min-remaining", "0s", "op://Automation"}
	if err := cmdRequest(args4); err != nil {
		t.Fatalf("reuse-disabled request: %v", err)
	}
	if n := requestCount(s); n != 4 {
		t.Fatalf("requests after reuse-disabled = %d, want 4", n)
	}
}
