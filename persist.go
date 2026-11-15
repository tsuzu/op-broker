package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Persistence for push device tokens — the ONE piece of broker state
// that survives a restart, by the owner's explicit choice. Everything
// else (backend credential, grants, audit, admin token) stays
// RAM-only as designed.
//
// Why tokens are safe to persist: an FCM registration token is a
// device address, not a credential. Holding one lets you do nothing
// without the Firebase service-account key (which stays in its k8s
// Secret), and a stale token is pruned when FCM reports it
// UNREGISTERED.
//
// The store is a single small JSON document on SeaweedFS S3
// (s3://op-broker/push-tokens.json), written through Web Identity:
// the pod's projected ServiceAccount token (audience "seaweedfs") is
// exchanged at the SeaweedFS STS endpoint for short-lived S3
// credentials — no static keys anywhere, the same pattern as the
// EPGStation stack. All of it is Go stdlib (SigV4 by hand).

type tokenStore interface {
	Load() ([]string, error)
	Save(tokens []string) error
}

type tokensFile struct {
	Tokens    []string `json:"tokens"`
	UpdatedAt string   `json:"updated_at"`
}

// --- SeaweedFS S3 via STS Web Identity ---

type stsCredentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	ExpiresAt    time.Time
}

type s3TokenStore struct {
	endpoint  string // e.g. http://10.24.0.138:8333
	bucket    string
	key       string
	roleArn   string
	tokenFile string
	http      *http.Client

	mu    sync.Mutex
	creds *stsCredentials
}

func newS3TokenStore(objectURL, roleArn, tokenFile string) (*s3TokenStore, error) {
	u, err := url.Parse(objectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("bad S3 object URL %q", objectURL)
	}
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("S3 object URL must be http://host/bucket/key, got %q", objectURL)
	}
	return &s3TokenStore{
		endpoint:  u.Scheme + "://" + u.Host,
		bucket:    parts[0],
		key:       parts[1],
		roleArn:   roleArn,
		tokenFile: tokenFile,
		http:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

type stsXML struct {
	Result struct {
		Credentials struct {
			AccessKey    string    `xml:"AccessKeyId"`
			SecretKey    string    `xml:"SecretAccessKey"`
			SessionToken string    `xml:"SessionToken"`
			Expiration   time.Time `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

func (st *s3TokenStore) credentials() (*stsCredentials, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.creds != nil && time.Until(st.creds.ExpiresAt) > 2*time.Minute {
		return st.creds, nil
	}
	jwt, err := os.ReadFile(st.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read web identity token: %w", err)
	}
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {st.roleArn},
		"RoleSessionName":  {"op-broker-push-tokens"},
		"WebIdentityToken": {strings.TrimSpace(string(jwt))},
		"DurationSeconds":  {"3600"},
	}
	resp, err := st.http.PostForm(st.endpoint+"/", form)
	if err != nil {
		return nil, fmt.Errorf("STS exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STS exchange: HTTP %d: %s", resp.StatusCode, body)
	}
	var parsed stsXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("STS response parse: %w", err)
	}
	c := parsed.Result.Credentials
	if c.AccessKey == "" {
		return nil, fmt.Errorf("STS response carried no credentials")
	}
	st.creds = &stsCredentials{AccessKey: c.AccessKey, SecretKey: c.SecretKey, SessionToken: c.SessionToken, ExpiresAt: c.Expiration}
	return st.creds, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// doSigned performs one SigV4-signed S3 request (path style).
func (st *s3TokenStore) doSigned(method, path string, body []byte) (int, []byte, error) {
	creds, err := st.credentials()
	if err != nil {
		return 0, nil, err
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256.Sum256(body)
	host := strings.TrimPrefix(strings.TrimPrefix(st.endpoint, "http://"), "https://")

	headers := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": hex.EncodeToString(payloadHash[:]),
		"x-amz-date":           amzDate,
		"x-amz-security-token": creds.SessionToken,
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		fmt.Fprintf(&canonHeaders, "%s:%s\n", n, headers[n])
	}
	signedHeaders := strings.Join(names, ";")
	canonReq := strings.Join([]string{method, path, "", canonHeaders.String(), signedHeaders, hex.EncodeToString(payloadHash[:])}, "\n")
	scope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", dateStamp)
	canonHash := sha256.Sum256([]byte(canonReq))
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(canonHash[:])}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+creds.SecretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte("us-east-1"))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequest(method, st.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for n, v := range headers {
		if n != "host" {
			req.Header.Set(n, v)
		}
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", creds.AccessKey, scope, signedHeaders, signature))
	resp, err := st.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, nil
}

func (st *s3TokenStore) Load() ([]string, error) {
	code, body, err := st.doSigned(http.MethodGet, "/"+st.bucket+"/"+st.key, nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		if strings.Contains(string(body), "NoSuchBucket") {
			// First run: create the bucket, then start empty.
			ccode, cbody, cerr := st.doSigned(http.MethodPut, "/"+st.bucket, nil)
			if cerr != nil {
				return nil, cerr
			}
			if ccode != http.StatusOK {
				return nil, fmt.Errorf("create bucket: HTTP %d: %s", ccode, cbody)
			}
			log.Printf("push token store: created bucket %s", st.bucket)
		}
		return nil, nil // NoSuchKey (or just-created bucket): no tokens yet
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("load push tokens: HTTP %d: %s", code, body)
	}
	var f tokensFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parse stored push tokens: %w", err)
	}
	return f.Tokens, nil
}

func (st *s3TokenStore) Save(tokens []string) error {
	data, err := json.Marshal(tokensFile{Tokens: tokens, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	code, body, err := st.doSigned(http.MethodPut, "/"+st.bucket+"/"+st.key, data)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("save push tokens: HTTP %d: %s", code, body)
	}
	return nil
}

// --- debounced saver ---

// pushPersister mirrors the in-memory token set into a tokenStore.
// Changes mark it dirty; a background loop (and flush()) writes the
// latest snapshot. Failures keep the dirty flag so the next tick
// retries; the in-memory set is never blocked by the store.
type pushPersister struct {
	store tokenStore
	get   func() []string
	dirty atomic.Bool
}

func (p *pushPersister) markDirty() { p.dirty.Store(true) }

func (p *pushPersister) flush() {
	if !p.dirty.Load() {
		return
	}
	p.dirty.Store(false)
	if err := p.store.Save(p.get()); err != nil {
		log.Printf("push token store: save failed (will retry): %v", err)
		p.dirty.Store(true)
	}
}

func (p *pushPersister) run() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		p.flush()
	}
}

// --- server wiring helpers ---

func (s *server) pushTokenList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.pushTokens))
	for t := range s.pushTokens {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (s *server) markPushDirty() {
	if s.persister != nil {
		s.persister.markDirty()
	}
}

// loadPushTokens restores registered device tokens from the store at
// startup. Failures are logged and the broker starts with an empty
// set (devices re-register when their dashboard is next opened).
func (s *server) loadPushTokens() {
	if s.persister == nil {
		return
	}
	tokens, err := s.persister.store.Load()
	if err != nil {
		log.Printf("push token store: load failed (starting empty): %v", err)
		return
	}
	s.mu.Lock()
	if s.pushTokens == nil {
		s.pushTokens = map[string]bool{}
	}
	for _, t := range tokens {
		s.pushTokens[t] = true
	}
	n := len(s.pushTokens)
	s.mu.Unlock()
	if n > 0 {
		log.Printf("push token store: restored %d device token(s)", n)
	}
}
