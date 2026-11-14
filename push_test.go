package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func pushServer(t *testing.T) (string, *server, *fakeGoogle) {
	t.Helper()
	base, s := newTestServer(t)
	f := newFakeGoogle(t)
	s.fcm = f.client(t)
	s.firebaseCfg = &firebaseWebConfig{
		APIKey: "k", AuthDomain: "d", ProjectID: "test-project",
		StorageBucket: "b", MessagingSenderID: "123", AppID: "app", VAPIDKey: "vapid",
	}
	return base, s, f
}

func TestPWAAssets(t *testing.T) {
	base, _, _ := pushServer(t)
	for _, tc := range []struct{ path, wantCT, wantInBody string }{
		{"/manifest.webmanifest", "application/manifest+json", `"standalone"`},
		{"/icon-192.png", "image/png", ""},
		{"/icon-512.png", "image/png", ""},
		{"/apple-touch-icon.png", "image/png", ""},
		{"/firebase-messaging-sw.js", "application/javascript", "onBackgroundMessage"},
	} {
		resp, err := http.Get(base + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s = %d", tc.path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.wantCT) {
			t.Fatalf("GET %s content-type %q, want %q", tc.path, ct, tc.wantCT)
		}
		if tc.wantInBody != "" && !strings.Contains(string(body), tc.wantInBody) {
			t.Fatalf("GET %s body missing %q", tc.path, tc.wantInBody)
		}
	}
	// The service worker embeds the Firebase config.
	resp, _ := http.Get(base + "/firebase-messaging-sw.js")
	swBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(swBody), "test-project") {
		t.Fatal("service worker does not embed the firebase config")
	}
	// The dashboard carries the manifest link and (push on) the enable UI.
	c := adminClient(t, base)
	resp, err := c.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	dash, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`rel="manifest"`, "pushBtn", "firebase-messaging-sw.js"} {
		if !strings.Contains(string(dash), want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
}

func TestPushRegisterAndNotify(t *testing.T) {
	base, s, f := pushServer(t)

	// Without an admin session: refused.
	resp, err := http.PostForm(base+"/push/register", url.Values{"token": {"device-token-xyz"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("register without session = %d, want 401", resp.StatusCode)
	}

	// With an admin session: stored.
	c := adminClient(t, base)
	resp, err = c.PostForm(base+"/push/register", url.Values{
		"csrf":  {csrfFor(t, c, base)},
		"token": {"device-token-xyz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	if !s.pushTokens["device-token-xyz"] {
		t.Fatal("token was not registered")
	}

	// A new client request triggers exactly one push, without the code.
	ticket := mkTicket(t)
	_, code := createRequest(t, base, ticket, []string{"op://milldea"})
	deadline := time.Now().Add(3 * time.Second)
	for f.sendHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.sendHits.Load() != 1 {
		t.Fatalf("push sends = %d, want 1", f.sendHits.Load())
	}
	msg, _ := f.lastBody["message"].(map[string]any)
	data, _ := msg["data"].(map[string]any)
	titleBody := data["title"].(string) + data["body"].(string)
	if !strings.Contains(titleBody, "test-mac") || !strings.Contains(titleBody, "op://milldea") {
		t.Fatalf("push content = %q", titleBody)
	}
	if strings.Contains(titleBody, code) {
		t.Fatal("push must not contain the pairing code")
	}

	// Unregister stops further pushes.
	resp, err = c.PostForm(base+"/push/unregister", url.Values{
		"csrf":  {csrfFor(t, c, base)},
		"token": {"device-token-xyz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unregister = %d", resp.StatusCode)
	}
	createRequest(t, base, mkTicket(t), []string{"op://milldea"})
	time.Sleep(400 * time.Millisecond)
	if f.sendHits.Load() != 1 {
		t.Fatalf("push sends after unregister = %d, want still 1", f.sendHits.Load())
	}
}
