package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyHeaderAuth(t *testing.T) {
	s := newServer(defaultMockBackend(), true, testAdmin)
	s.trustProxyHeader = "X-Auth-Request-User"

	mkReq := func(remote, user string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if user != "" {
			r.Header.Set("X-Auth-Request-User", user)
		}
		return r
	}
	w := httptest.NewRecorder()

	// Loopback + header: authenticated, and the session is stable so the
	// dashboard's CSRF token keeps matching across requests.
	sess1, ok := s.adminAuth(w, mkReq("127.0.0.1:40001", "Tsuzu"))
	if !ok {
		t.Fatal("loopback proxy header request was not authenticated")
	}
	sess2, ok := s.adminAuth(w, mkReq("127.0.0.1:40002", "Tsuzu"))
	if !ok || sess2 != sess1 {
		t.Fatal("proxy session is not stable across requests")
	}
	if !s.checkCSRF(mkReqWithCSRF(sess1.CSRF), sess1) {
		t.Fatal("proxy session CSRF does not validate")
	}

	// Same header from a non-loopback peer must be ignored (spoofing).
	if _, ok := s.adminAuth(w, mkReq("10.24.0.55:40001", "Tsuzu")); ok {
		t.Fatal("proxy header from non-loopback peer was trusted")
	}
	// Loopback without the header: not authenticated.
	if _, ok := s.adminAuth(w, mkReq("127.0.0.1:40001", "")); ok {
		t.Fatal("loopback request without header was authenticated")
	}
	// Feature off entirely: header never trusted.
	s2 := newServer(defaultMockBackend(), true, testAdmin)
	if _, ok := s2.adminAuth(w, mkReq("127.0.0.1:40001", "Tsuzu")); ok {
		t.Fatal("proxy header trusted while trustProxyHeader is unset")
	}
}

func mkReqWithCSRF(csrf string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/approve", nil)
	r.Form = map[string][]string{"csrf": {csrf}}
	return r
}
