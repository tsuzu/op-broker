package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testAdmin = "test-admin-token"

func newTestServer(t *testing.T) (string, *server) {
	t.Helper()
	s := newServer(defaultMockBackend(), true, testAdmin)
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return ts.URL, s
}

func adminClient(t *testing.T, base string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(base+"/login", url.Values{"admin_token": {testAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	// fetch dashboard to obtain the CSRF token
	resp, err = c.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// stash csrf in a cookie-like place: simplest is to parse and store globally per client via header trick
	_ = body
	return c
}

func csrfFor(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	resp, err := c.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	const marker = `name="csrf" value="`
	i := strings.Index(s, marker)
	if i < 0 {
		t.Fatal("csrf not found in dashboard")
	}
	rest := s[i+len(marker):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

func unlock(t *testing.T, c *http.Client, base string) {
	t.Helper()
	csrf := csrfFor(t, c, base)
	resp, err := c.PostForm(base+"/unlock", url.Values{
		"csrf":       {csrf},
		"credential": {"demo-credential"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock status %d", resp.StatusCode)
	}
}

func mkTicket(t *testing.T) string {
	t.Helper()
	tk, err := newTicket()
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func createRequest(t *testing.T, base, ticket string, scopes []string) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"ticket_hash": ticketHash(ticket),
		"client_name": "test-mac",
		"host":        "testhost",
		"reason":      "unit test",
		"scopes":      scopes,
		"ttl_seconds": 3600,
	})
	resp, err := http.Post(base+"/api/requests", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create request status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	// The code the client computes locally must match the server's.
	if want := pairingCode(ticketHash(ticket)); out.Code != want {
		t.Fatalf("pairing code mismatch: server %s client %s", out.Code, want)
	}
	return out.RequestID, out.Code
}

func doRead(base, ticket, ref string) (int, string) {
	body, _ := json.Marshal(map[string]string{"ref": ref})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/read", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	var out struct {
		Value string `json:"value"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Value != "" {
		return resp.StatusCode, out.Value
	}
	return resp.StatusCode, out.Error
}

func approve(t *testing.T, c *http.Client, base, reqID string, ttlSeconds string) {
	t.Helper()
	csrf := csrfFor(t, c, base)
	resp, err := c.PostForm(base+"/approve", url.Values{
		"csrf":        {csrf},
		"request_id":  {reqID},
		"ttl_seconds": {ttlSeconds},
		"max_reads":   {"10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status %d", resp.StatusCode)
	}
}

func TestFullFlow(t *testing.T) {
	base, _ := newTestServer(t)
	admin := adminClient(t, base)
	ticket := mkTicket(t)
	scopes := []string{"op://Automation/demo/password"}

	// While locked, reads are refused even before any grant exists.
	if code, msg := doRead(base, ticket, scopes[0]); code != http.StatusLocked {
		t.Fatalf("locked read: got %d (%s), want 423", code, msg)
	}
	reqID, _ := createRequest(t, base, ticket, scopes)
	unlock(t, admin, base)

	// Pending: not yet approved.
	if code, _ := doRead(base, ticket, scopes[0]); code == http.StatusOK {
		t.Fatal("read succeeded before approval")
	}
	approve(t, admin, base, reqID, "3600")

	code, val := doRead(base, ticket, scopes[0])
	if code != http.StatusOK || val != "demo-password-value" {
		t.Fatalf("approved read: got %d %q", code, val)
	}
	// Out of scope must be refused.
	if code, _ := doRead(base, ticket, "op://Automation/demo/api-key"); code != http.StatusForbidden {
		t.Fatalf("out-of-scope read: got %d, want 403", code)
	}
	// Unknown ticket must be refused.
	if code, _ := doRead(base, mkTicket(t), scopes[0]); code == http.StatusOK {
		t.Fatal("read with unknown ticket succeeded")
	}
}

func TestDenyAndRevokeAndExpiry(t *testing.T) {
	base, _ := newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	scopes := []string{"op://Automation/demo/password"}

	// Deny path.
	t1 := mkTicket(t)
	r1, _ := createRequest(t, base, t1, scopes)
	csrf := csrfFor(t, admin, base)
	resp, err := admin.PostForm(base+"/deny", url.Values{"csrf": {csrf}, "request_id": {r1}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, _ := doRead(base, t1, scopes[0]); code == http.StatusOK {
		t.Fatal("read succeeded after deny")
	}

	// Revoke path.
	t2 := mkTicket(t)
	r2, _ := createRequest(t, base, t2, scopes)
	approve(t, admin, base, r2, "3600")
	if code, _ := doRead(base, t2, scopes[0]); code != http.StatusOK {
		t.Fatalf("read before revoke: %d", code)
	}
	// find grant id via server state through status endpoint is not exposed; use dashboard HTML
	resp, err = admin.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	htmlBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(htmlBytes)
	const gm = `name="grant_id" value="`
	gi := strings.Index(html, gm)
	if gi < 0 {
		t.Fatal("grant id not in dashboard")
	}
	gid := html[gi+len(gm):]
	gid = gid[:strings.Index(gid, `"`)]
	csrf = csrfFor(t, admin, base)
	resp, err = admin.PostForm(base+"/revoke", url.Values{"csrf": {csrf}, "grant_id": {gid}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, _ := doRead(base, t2, scopes[0]); code == http.StatusOK {
		t.Fatal("read succeeded after revoke")
	}

	// Expiry path: approve with a 1-second TTL, then wait it out.
	t3 := mkTicket(t)
	r3, _ := createRequest(t, base, t3, scopes)
	approve(t, admin, base, r3, "1")
	if code, _ := doRead(base, t3, scopes[0]); code != http.StatusOK {
		t.Fatalf("read within ttl: %d", code)
	}
	time.Sleep(1100 * time.Millisecond)
	if code, _ := doRead(base, t3, scopes[0]); code == http.StatusOK {
		t.Fatal("read succeeded after grant expiry")
	}
}

func TestLockRevokesEverything(t *testing.T) {
	base, _ := newTestServer(t)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	ticket := mkTicket(t)
	scopes := []string{"op://Automation/demo/password"}
	reqID, _ := createRequest(t, base, ticket, scopes)
	approve(t, admin, base, reqID, "3600")
	if code, _ := doRead(base, ticket, scopes[0]); code != http.StatusOK {
		t.Fatalf("pre-lock read: %d", code)
	}
	csrf := csrfFor(t, admin, base)
	resp, err := admin.PostForm(base+"/lock", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code, _ := doRead(base, ticket, scopes[0]); code != http.StatusLocked {
		t.Fatalf("post-lock read: got %d, want 423", code)
	}
}
