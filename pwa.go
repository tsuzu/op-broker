package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// PWA support: the dashboard can be added to the home screen (required
// for Web Push on iOS) and registers a service worker that receives FCM
// pushes. Assets are public (no secrets in them); the oauth2-proxy in
// front may still gate them, which is fine — they are fetched with the
// owner's session.

//go:embed assets/icon-192.png
var icon192PNG []byte

//go:embed assets/icon-512.png
var icon512PNG []byte

//go:embed assets/apple-touch-icon.png
var appleTouchIconPNG []byte

const manifestJSON = `{
  "name": "op-broker",
  "short_name": "op-broker",
  "description": "Approval-gated 1Password secrets broker",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#0f172a",
  "theme_color": "#0f172a",
  "icons": [
    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ]
}`

// serviceWorkerJS renders the combined service worker: Firebase
// messaging (background pushes) + notification click handling + an
// immediate-activation lifecycle. cfgJSON is the public web config.
func serviceWorkerJS(cfgJSON string) string {
	return `importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-messaging-compat.js');
firebase.initializeApp(` + cfgJSON + `);
const messaging = firebase.messaging();
messaging.onBackgroundMessage((payload) => {
  const d = payload.data || {};
  const title = d.title || 'op-broker';
  return self.registration.showNotification(title, {
    body: d.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: { url: d.url || '/' }
  });
});
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.startsWith(self.location.origin)) { c.focus(); return; }
      }
      return clients.openWindow(url);
    })
  );
});
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(clients.claim()));
`
}

func (s *server) handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Write([]byte(manifestJSON))
}

func iconHandler(png []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(png)
	}
}

func (s *server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	if s.firebaseCfg == nil {
		http.Error(w, "push not configured", http.StatusNotFound)
		return
	}
	cfg, _ := json.Marshal(s.firebaseCfg)
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Write([]byte(serviceWorkerJS(string(cfg))))
}

// --- push token registry (RAM only, like everything else) ---

func (s *server) handlePushRegister(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if len(token) < 10 || len(token) > 4096 {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.pushTokens == nil {
		s.pushTokens = map[string]bool{}
	}
	s.pushTokens[token] = true
	n := len(s.pushTokens)
	s.mu.Unlock()
	log.Printf("push device registered (%d total)", n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "devices": n})
}

func (s *server) handlePushUnregister(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	s.mu.Lock()
	delete(s.pushTokens, token)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// notifyNewRequest pushes "a request is waiting" to every registered
// device. The pairing code is deliberately NOT included: a lock-screen
// notification must not carry it — the owner matches the code in the
// dashboard. Runs in its own goroutine; failures are logged only.
func (s *server) notifyNewRequest(req *accessRequest) {
	if s.fcm == nil {
		return
	}
	s.mu.Lock()
	tokens := make([]string, 0, len(s.pushTokens))
	for t := range s.pushTokens {
		tokens = append(tokens, t)
	}
	s.mu.Unlock()
	if len(tokens) == 0 {
		return
	}
	title := "op-broker: 承認リクエスト"
	body := fmt.Sprintf("%s (%s): %s", req.ClientName, req.Host, strings.Join(req.Scopes, ", "))
	if req.Reason != "" {
		body += " / " + req.Reason
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, t := range tokens {
		err := s.fcm.send(ctx, t, title, body, "/")
		if err != nil {
			log.Printf("push send failed: %v", err)
			if errors.Is(err, errTokenUnregistered) {
				s.mu.Lock()
				delete(s.pushTokens, t)
				s.mu.Unlock()
				log.Printf("push device pruned (unregistered)")
			}
		}
	}
}
