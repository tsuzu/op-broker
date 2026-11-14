package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func renewCall(t *testing.T, base, ticket string, ttlSeconds int) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ttl_seconds": ttlSeconds})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/renew", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func statusOf(t *testing.T, base, ticket string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+ticket)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenewFlow(t *testing.T) {
	base, s := newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	ticket := mkTicket(t)
	reqID, _ := createRequest(t, base, ticket, []string{"op://Automation/demo"})
	approve(t, admin, base, reqID, "3600")
	if code, _ := doRead(base, ticket, "op://Automation/demo/api-key"); code != 200 {
		t.Fatalf("initial read = %d", code)
	}

	// Force the grant to expire; reads now fail.
	s.mu.Lock()
	var gid string
	for id, g := range s.grants {
		g.ExpiresAt = time.Now().Add(-time.Minute)
		gid = id
	}
	s.mu.Unlock()
	if code, _ := doRead(base, ticket, "op://Automation/demo/api-key"); code == 200 {
		t.Fatal("read succeeded on an expired grant")
	}

	// Renewal: pending until approved, then the same ticket reads again.
	code, out := renewCall(t, base, ticket, 3600)
	if code != http.StatusCreated {
		t.Fatalf("renew = %d: %v", code, out)
	}
	renewID, _ := out["request_id"].(string)
	if st := statusOf(t, base, ticket); st["status"] != "pending" {
		t.Fatalf("status during renewal = %v, want pending", st["status"])
	}
	if code, _ := doRead(base, ticket, "op://Automation/demo/api-key"); code == 200 {
		t.Fatal("read succeeded while renewal still pending")
	}
	approve(t, admin, base, renewID, "3600")
	st := statusOf(t, base, ticket)
	if st["status"] != "approved" {
		t.Fatalf("status after renewal = %v", st["status"])
	}
	exp, _ := st["grant_expires_at"].(string)
	expT, err := time.Parse(time.RFC3339, exp)
	if err != nil || !time.Now().Before(expT) {
		t.Fatalf("grant_expires_at after renewal = %q", exp)
	}
	if code, val := doRead(base, ticket, "op://Automation/demo/api-key"); code != 200 || val != "demo-api-key-12345" {
		t.Fatalf("read after renewal = %d %q", code, val)
	}

	// Unknown ticket: no grant to renew.
	if code, _ := renewCall(t, base, mkTicket(t), 3600); code != http.StatusNotFound {
		t.Fatalf("renew with unknown ticket = %d, want 404", code)
	}

	// Revoked grant: renewal refused.
	csrf := csrfFor(t, admin, base)
	resp, err := admin.PostForm(base+"/revoke", url.Values{"csrf": {csrf}, "grant_id": {gid}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, _ := renewCall(t, base, ticket, 3600); code != http.StatusNotFound {
		t.Fatalf("renew of revoked grant = %d, want 404", code)
	}
	_ = gid
}

func TestGrantAddScope(t *testing.T) {
	base, s := newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	ticket := mkTicket(t)
	reqID, _ := createRequest(t, base, ticket, []string{"op://Automation/demo/api-key"})
	approve(t, admin, base, reqID, "3600")

	// The password field is outside the granted scope.
	if code, _ := doRead(base, ticket, "op://Automation/demo/password"); code != http.StatusForbidden {
		t.Fatalf("out-of-scope read = %d, want 403", code)
	}
	s.mu.Lock()
	var gid string
	for id := range s.grants {
		gid = id
	}
	s.mu.Unlock()

	addScope := func(scope string) int {
		resp, err := admin.PostForm(base+"/grant/add-scope", url.Values{
			"csrf":     {csrfFor(t, admin, base)},
			"grant_id": {gid},
			"scope":    {scope},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := addScope("not-a-ref"); code != http.StatusBadRequest {
		t.Fatalf("add invalid scope = %d, want 400", code)
	}
	if code := addScope("op://Automation/demo/password"); code != http.StatusOK && code != http.StatusSeeOther {
		t.Fatalf("add scope = %d", code)
	}
	if code, val := doRead(base, ticket, "op://Automation/demo/password"); code != 200 || val != "demo-password-value" {
		t.Fatalf("read after scope-add = %d %q", code, val)
	}
	// Adding an already-covered scope is a no-op success.
	if code := addScope("op://Automation/demo/password"); code != http.StatusOK && code != http.StatusSeeOther {
		t.Fatalf("re-add covered scope = %d", code)
	}
	// Audited.
	s.mu.Lock()
	found := false
	for _, a := range s.audit {
		if a.Result == "scope-added" && a.Ref == "op://Automation/demo/password" {
			found = true
		}
	}
	s.mu.Unlock()
	if !found {
		t.Fatal("scope-added was not audited")
	}
}
