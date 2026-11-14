package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeGoogle stands in for the OAuth2 token endpoint and the FCM send
// endpoint, verifying the broker's JWT and capturing what it sends.
type fakeGoogle struct {
	key       *rsa.PrivateKey
	tokenHits atomic.Int32
	sendHits  atomic.Int32
	lastAuth  string
	lastBody  map[string]any
	unreg     atomic.Bool
	srv       *httptest.Server
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		assertion := r.FormValue("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("assertion is not a JWT: %q", assertion)
			http.Error(w, "bad", 400)
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig); err != nil {
			t.Errorf("JWT signature does not verify: %v", err)
			http.Error(w, "bad sig", 400)
			return
		}
		claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(claimsJSON, &claims)
		if claims["iss"] != "svc@test-project.iam.gserviceaccount.com" {
			t.Errorf("iss = %v", claims["iss"])
		}
		if claims["scope"] != "https://www.googleapis.com/auth/firebase.messaging" {
			t.Errorf("scope = %v", claims["scope"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"ya29.test-token","expires_in":3600}`))
	})
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		f.sendHits.Add(1)
		f.lastAuth = r.Header.Get("Authorization")
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &f.lastBody)
		w.Header().Set("Content-Type", "application/json")
		if f.unreg.Load() {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":{"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`))
			return
		}
		w.Write([]byte(`{"name":"projects/test-project/messages/1"}`))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) client(t *testing.T) *fcmClient {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	saJSON, _ := json.Marshal(map[string]string{
		"project_id":   "test-project",
		"client_email": "svc@test-project.iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":    f.srv.URL + "/token",
	})
	c, err := newFCMClient(saJSON)
	if err != nil {
		t.Fatal(err)
	}
	c.sendURL = f.srv.URL + "/send"
	return c
}

func TestFCMSendAndTokenCaching(t *testing.T) {
	f := newFakeGoogle(t)
	c := f.client(t)
	ctx := context.Background()
	if err := c.send(ctx, "device-token-1", "タイトル", "本文", "/"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if f.lastAuth != "Bearer ya29.test-token" {
		t.Fatalf("auth header = %q", f.lastAuth)
	}
	msg, _ := f.lastBody["message"].(map[string]any)
	if msg["token"] != "device-token-1" {
		t.Fatalf("message.token = %v", msg["token"])
	}
	data, _ := msg["data"].(map[string]any)
	if data["title"] != "タイトル" || data["body"] != "本文" || data["url"] != "/" {
		t.Fatalf("message.data = %v", data)
	}
	if _, hasNotification := msg["notification"]; hasNotification {
		t.Fatal("message must be data-only (no notification payload)")
	}
	// Second send reuses the cached access token.
	if err := c.send(ctx, "device-token-1", "t2", "b2", "/"); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	if got := f.tokenHits.Load(); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cached)", got)
	}
	if got := f.sendHits.Load(); got != 2 {
		t.Fatalf("send hits = %d, want 2", got)
	}
}

func TestFCMUnregisteredIsPrunable(t *testing.T) {
	f := newFakeGoogle(t)
	f.unreg.Store(true)
	c := f.client(t)
	err := c.send(context.Background(), "dead-token", "t", "b", "/")
	if !errors.Is(err, errTokenUnregistered) {
		t.Fatalf("err = %v, want errTokenUnregistered", err)
	}
}

func TestLoadFirebaseConfig(t *testing.T) {
	if _, err := loadFirebaseConfig([]byte(`{"projectId":"p"}`)); err == nil {
		t.Fatal("incomplete config was accepted")
	}
	cfg, err := loadFirebaseConfig([]byte(`{"apiKey":"k","authDomain":"d","projectId":"p","storageBucket":"b","messagingSenderId":"123","appId":"1:123:web:abc","vapidKey":"BN..."}`))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.ProjectID != "p" || cfg.VAPIDKey != "BN..." {
		t.Fatalf("cfg = %+v", cfg)
	}
}
