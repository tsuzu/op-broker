package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSourceIP(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/requests", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"via proxy uses first XFF", "127.0.0.1:5000", "203.0.113.9, 10.0.0.1", "203.0.113.9"},
		{"via proxy no XFF falls back to peer", "127.0.0.1:5000", "", "127.0.0.1"},
		{"direct peer ignores spoofed XFF", "192.0.2.44:5000", "203.0.113.9", "192.0.2.44"},
		{"ipv6 loopback via proxy", "[::1]:5000", "2001:db8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := sourceIP(mk(c.remote, c.xff)); got != c.want {
			t.Errorf("%s: sourceIP = %q, want %q", c.name, got, c.want)
		}
	}
}
