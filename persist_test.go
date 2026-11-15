package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSeaweed stands in for the SeaweedFS STS + S3 endpoints.
type fakeSeaweed struct {
	mu      sync.Mutex
	buckets map[string]map[string][]byte
	stsHits int
}

func (f *fakeSeaweed) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/" {
		_ = r.ParseForm()
		if r.FormValue("Action") != "AssumeRoleWithWebIdentity" || r.FormValue("WebIdentityToken") == "" {
			http.Error(w, "bad sts request", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.stsHits++
		f.mu.Unlock()
		exp := time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AKTEST</AccessKeyId><SecretAccessKey>SKTEST</SecretAccessKey><SessionToken>TOKTEST</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, exp)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, "missing sig", http.StatusForbidden)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	bucket := parts[0]
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPut && len(parts) == 1:
		if f.buckets[bucket] == nil {
			f.buckets[bucket] = map[string][]byte{}
		}
		w.WriteHeader(http.StatusOK)
	case len(parts) == 2 && r.Method == http.MethodPut:
		if f.buckets[bucket] == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.buckets[bucket][parts[1]] = body
		w.WriteHeader(http.StatusOK)
	case len(parts) == 2 && r.Method == http.MethodGet:
		if f.buckets[bucket] == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code></Error>`)
			return
		}
		data, ok := f.buckets[bucket][parts[1]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		_, _ = w.Write(data)
	default:
		http.Error(w, "unhandled", http.StatusBadRequest)
	}
}

func TestS3TokenStoreRoundTrip(t *testing.T) {
	fake := &fakeSeaweed{buckets: map[string]map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	tokenFile := t.TempDir() + "/token"
	writeFile(t, tokenFile, "fake-sa-jwt")
	objURL := srv.URL + "/op-broker/push-tokens.json"

	st, err := newS3TokenStore(objURL, "arn:aws:iam::123456789012:role/S3AdminRole", tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("initial load = %v, want empty", got)
	}
	if err := st.Save([]string{"tok-b", "tok-a"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// A fresh store instance (fresh credential cache) reads it back.
	st2, err := newS3TokenStore(objURL, "arn:aws:iam::123456789012:role/S3AdminRole", tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err = st2.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "tok-a" || got[1] != "tok-b" {
		t.Fatalf("reloaded tokens = %v", got)
	}
	if fake.stsHits == 0 {
		t.Fatal("STS was never called")
	}
}

// memStore is an in-memory tokenStore for the server-wiring test.
type memStore struct {
	mu     sync.Mutex
	tokens []string
}

func (m *memStore) Load() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.tokens...), nil
}

func (m *memStore) Save(tokens []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = append([]string{}, tokens...)
	return nil
}

func TestPushTokensSurviveServerRestart(t *testing.T) {
	base, s := newTestServer(t)
	admin := adminClient(t, base)
	store := &memStore{}
	s.persister = &pushPersister{store: store, get: s.pushTokenList}

	resp, err := admin.PostForm(base+"/push/register", url.Values{
		"csrf":  {csrfFor(t, admin, base)},
		"token": {"device-token-1234567890"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	s.persister.flush()
	if len(store.tokens) != 1 || store.tokens[0] != "device-token-1234567890" {
		t.Fatalf("stored tokens = %v", store.tokens)
	}

	// A "restarted" broker restores the registration from the store.
	s2 := newServer(defaultMockBackend(), true, "admin-x")
	s2.persister = &pushPersister{store: store, get: s2.pushTokenList}
	s2.loadPushTokens()
	if !s2.pushTokens["device-token-1234567890"] {
		t.Fatalf("restored tokens = %v", s2.pushTokens)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
