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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Firebase Cloud Messaging support: when a client creates a request, the
// owner gets a Web Push on the dashboard PWA (iPhone home-screen app or
// desktop browser), so approvals do not sit unseen. Sending uses the FCM
// HTTP v1 API with a Google service-account key, implemented with the
// standard library only (RS256 JWT -> OAuth2 access token -> send).
//
// Messages are data-only: title/body travel in the data payload and the
// service worker renders the notification itself, which behaves the
// same on Chrome and on iOS PWAs.

// firebaseWebConfig is the Firebase web-app configuration (public
// identifiers, safe to embed in the dashboard HTML) plus the VAPID
// public key used for Web Push subscription.
type firebaseWebConfig struct {
	APIKey            string `json:"apiKey"`
	AuthDomain        string `json:"authDomain"`
	ProjectID         string `json:"projectId"`
	StorageBucket     string `json:"storageBucket"`
	MessagingSenderID string `json:"messagingSenderId"`
	AppID             string `json:"appId"`
	VAPIDKey          string `json:"vapidKey"`
}

func loadFirebaseConfig(data []byte) (*firebaseWebConfig, error) {
	var cfg firebaseWebConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("firebase config: %w", err)
	}
	if cfg.ProjectID == "" || cfg.APIKey == "" || cfg.MessagingSenderID == "" || cfg.AppID == "" || cfg.VAPIDKey == "" {
		return nil, errors.New("firebase config is missing required fields (projectId, apiKey, messagingSenderId, appId, vapidKey)")
	}
	return &cfg, nil
}

var errTokenUnregistered = errors.New("fcm: registration token no longer registered")

type fcmClient struct {
	project  string
	email    string
	key      *rsa.PrivateKey
	tokenURL string
	sendURL  string
	http     *http.Client

	mu        sync.Mutex
	accessTok string
	accessExp time.Time
}

func newFCMClient(saJSON []byte) (*fcmClient, error) {
	var sa struct {
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("service account json: %w", err)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("service account json is missing project_id, client_email or private_key")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("service account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service account private_key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service account private_key is not RSA")
	}
	tokenURL := sa.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	return &fcmClient{
		project:  sa.ProjectID,
		email:    sa.ClientEmail,
		key:      rsaKey,
		tokenURL: tokenURL,
		sendURL:  "https://fcm.googleapis.com/v1/projects/" + sa.ProjectID + "/messages:send",
		http:     &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (c *fcmClient) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessTok != "" && time.Now().Add(time.Minute).Before(c.accessExp) {
		return c.accessTok, nil
	}
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iss":   c.email,
		"scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud":   c.tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signing := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	assertion := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth2 token exchange failed (%d): %s", resp.StatusCode, data)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("oauth2 token exchange: bad response: %s", data)
	}
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = 3600
	}
	c.accessTok = tok.AccessToken
	c.accessExp = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.accessTok, nil
}

// send delivers one data-only message. It returns errTokenUnregistered
// (wrapped) when FCM says the device token is gone, so the caller can
// prune it.
func (c *fcmClient) send(ctx context.Context, deviceToken, title, body, link string) error {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	msg := map[string]any{
		"message": map[string]any{
			"token": deviceToken,
			"data":  map[string]string{"title": title, "body": body, "url": link},
			"webpush": map[string]any{
				"headers": map[string]string{"Urgency": "high"},
			},
		},
	}
	data, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sendURL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respData, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(respData, &e)
	for _, d := range e.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			return fmt.Errorf("%w (fcm %d)", errTokenUnregistered, resp.StatusCode)
		}
	}
	if e.Error.Status == "NOT_FOUND" {
		return fmt.Errorf("%w (fcm %d)", errTokenUnregistered, resp.StatusCode)
	}
	return fmt.Errorf("fcm send failed (%d): %s", resp.StatusCode, respData)
}
