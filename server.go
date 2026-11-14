package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// In-memory state. Nothing in this file ever touches the disk: the backend
// credential, admin sessions, pending requests, grants and the audit log all
// live in RAM and vanish when the process exits. That is a design property,
// not an omission.
// ---------------------------------------------------------------------------

const (
	pendingTTL      = 5 * time.Minute
	adminSessionTTL = 12 * time.Hour
	maxAudit        = 200
)

type reqStatus string

const (
	stPending  reqStatus = "pending"
	stApproved reqStatus = "approved"
	stDenied   reqStatus = "denied"
	stExpired  reqStatus = "expired"
)

type accessRequest struct {
	ID           string
	TicketHash   string // hex(sha256(ticket)); the ticket itself is never sent at request time
	Code         string // 6-digit pairing code derived from the ticket hash
	ClientName   string
	Host         string
	Reason       string
	Scopes       []string
	RequestedTTL time.Duration
	CreatedAt    time.Time
	Status       reqStatus
	GrantID      string
}

type grant struct {
	ID         string
	TicketHash string
	ClientName string
	Scopes     []string
	ExpiresAt  time.Time
	ReadsLeft  int
	Revoked    bool
}

func (g *grant) active(now time.Time) bool {
	return !g.Revoked && now.Before(g.ExpiresAt) && g.ReadsLeft > 0
}

type auditEntry struct {
	At     time.Time
	Client string
	Ref    string
	Result string // ok / denied-scope / locked / expired / backend-error
}

type adminSession struct {
	CSRF    string
	Expires time.Time
}

type server struct {
	backend Backend
	demo    bool

	adminTokenHash [32]byte

	mu         sync.Mutex
	credential string // backend credential, RAM only; "" means locked
	requests   map[string]*accessRequest
	byTicket   map[string]*accessRequest // ticketHash -> latest request
	grants     map[string]*grant         // grant ID -> grant
	grantByTkt map[string]*grant         // ticketHash -> grant
	sessions   map[string]*adminSession
	audit      []auditEntry

	// trustProxyHeader, when set (e.g. "X-Auth-Request-User"), treats a
	// request as admin-authenticated if it carries that header AND arrives
	// from a loopback address — i.e. from a reverse proxy in the same
	// network namespace (an oauth2-proxy sidecar) that performed the real
	// login. The header from any non-loopback peer is ignored, so the
	// gate cannot be spoofed from another pod or host.
	trustProxyHeader string
}

func newServer(backend Backend, demo bool, adminToken string) *server {
	return &server{
		backend:        backend,
		demo:           demo,
		adminTokenHash: sha256.Sum256([]byte(adminToken)),
		requests:       map[string]*accessRequest{},
		byTicket:       map[string]*accessRequest{},
		grants:         map[string]*grant{},
		grantByTkt:     map[string]*grant{},
		sessions:       map[string]*adminSession{},
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func ticketHash(ticket string) string {
	h := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(h[:])
}

// pairingCode derives the 6-digit code both sides can compute: the client
// from its ticket, the server from the ticket hash it received.
func pairingCode(hashHex string) string {
	b, err := hex.DecodeString(hashHex)
	if err != nil || len(b) < 4 {
		return "000000"
	}
	n := binary.BigEndian.Uint32(b[:4]) % 1000000
	return fmt.Sprintf("%06d", n)
}

// validScope accepts exact references and broader patterns:
//
//	op://Vault/Item/field   one field (exact)
//	op://Vault/Item         the whole item (all fields)
//	op://Vault              the whole vault
//	op://Vault/*            the whole vault (explicit wildcard)
//	op://*                  everything the backend credential can see
//
// A "*" segment is only allowed as the final segment.
func validScope(ref string) bool {
	if !strings.HasPrefix(ref, "op://") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 1 {
		return false
	}
	for i, p := range parts {
		if strings.TrimSpace(p) == "" {
			return false
		}
		if p == "*" && i != len(parts)-1 {
			return false
		}
	}
	return true
}

// scopeMatches reports whether any granted scope pattern covers ref.
// Matching is segment-aware: "op://Vault" does not match
// "op://VaultEvil/...".
func scopeMatches(scopes []string, ref string) bool {
	for _, p := range scopes {
		if patternMatches(p, ref) {
			return true
		}
	}
	return false
}

func patternMatches(pattern, ref string) bool {
	if pattern == ref {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		// Keep the trailing slash: "op://Vault/*" covers "op://Vault/…".
		return strings.HasPrefix(ref, pattern[:len(pattern)-1])
	}
	// Hierarchical scope: a vault or item pattern covers everything
	// below it at a segment boundary.
	return strings.HasPrefix(ref, pattern+"/")
}

// ---------------------------------------------------------------------------
// Client API
// ---------------------------------------------------------------------------

type requestBody struct {
	TicketHash string   `json:"ticket_hash"`
	ClientName string   `json:"client_name"`
	Host       string   `json:"host"`
	Reason     string   `json:"reason"`
	Scopes     []string `json:"scopes"`
	TTLSeconds int      `json:"ttl_seconds"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body requestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if len(body.TicketHash) != 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket_hash must be hex(sha256(ticket))"})
		return
	}
	if _, err := hex.DecodeString(body.TicketHash); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket_hash must be hex"})
		return
	}
	if len(body.Scopes) == 0 || len(body.Scopes) > 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scopes must contain 1..32 references"})
		return
	}
	for _, sc := range body.Scopes {
		if !validScope(sc) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scope reference: " + sc})
			return
		}
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = time.Hour
	}
	now := time.Now()
	req := &accessRequest{
		ID:           randHex(4),
		TicketHash:   strings.ToLower(body.TicketHash),
		Code:         pairingCode(body.TicketHash),
		ClientName:   truncate(body.ClientName, 64),
		Host:         truncate(body.Host, 128),
		Reason:       truncate(body.Reason, 256),
		Scopes:       body.Scopes,
		RequestedTTL: ttl,
		CreatedAt:    now,
		Status:       stPending,
	}
	s.mu.Lock()
	// One live request per ticket: a re-request supersedes the old one.
	if old, ok := s.byTicket[req.TicketHash]; ok && old.Status == stPending {
		old.Status = stExpired
	}
	s.requests[req.ID] = req
	s.byTicket[req.TicketHash] = req
	s.mu.Unlock()
	log.Printf("request %s from client=%q host=%q scopes=%d code=%s", req.ID, req.ClientName, req.Host, len(req.Scopes), req.Code)
	writeJSON(w, http.StatusCreated, map[string]any{
		"request_id": req.ID,
		"code":       req.Code,
		"expires_at": now.Add(pendingTTL).Format(time.RFC3339),
	})
}

func (s *server) bearerTicket(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	return t, t != ""
}

// refreshLocked expires stale pending requests. Caller holds s.mu.
func (s *server) refreshLocked(now time.Time) {
	for _, req := range s.requests {
		if req.Status == stPending && now.After(req.CreatedAt.Add(pendingTTL)) {
			req.Status = stExpired
		}
	}
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ticket, ok := s.bearerTicket(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing ticket"})
		return
	}
	th := ticketHash(ticket)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(now)
	req, ok := s.byTicket[th]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown ticket"})
		return
	}
	resp := map[string]any{"status": string(req.Status), "request_id": req.ID}
	if req.Status == stApproved {
		if g, ok := s.grantByTkt[th]; ok {
			resp["grant_expires_at"] = g.ExpiresAt.Format(time.RFC3339)
			resp["reads_left"] = g.ReadsLeft
			resp["scopes"] = g.Scopes
			if !g.active(now) {
				resp["status"] = "expired"
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ticket, ok := s.bearerTicket(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing ticket"})
		return
	}
	var body struct {
		Ref string `json:"ref"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil || body.Ref == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"ref\": \"op://...\"}"})
		return
	}
	th := ticketHash(ticket)
	now := time.Now()

	s.mu.Lock()
	cred := s.credential
	g, gok := s.grantByTkt[th]
	client := ""
	result := ""
	if gok {
		client = g.ClientName
	}
	switch {
	case cred == "":
		result = "locked"
	case !gok || !g.active(now):
		result = "expired"
	case !scopeMatches(g.Scopes, body.Ref):
		result = "denied-scope"
	default:
		g.ReadsLeft--
	}
	s.mu.Unlock()

	if result != "" {
		s.addAudit(client, body.Ref, result)
		code := http.StatusForbidden
		if result == "locked" {
			code = http.StatusLocked
		}
		writeJSON(w, code, map[string]string{"error": "read refused: " + result})
		return
	}
	val, err := s.backend.Read(context.Background(), cred, body.Ref)
	if err != nil {
		s.addAudit(client, body.Ref, "backend-error")
		// The read slot was already consumed; refund it on backend errors so a
		// transient failure does not burn the grant.
		s.mu.Lock()
		g.ReadsLeft++
		s.mu.Unlock()
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.addAudit(client, body.Ref, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"value": val})
}

func (s *server) addAudit(client, ref, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, auditEntry{At: time.Now(), Client: client, Ref: ref, Result: result})
	if len(s.audit) > maxAudit {
		s.audit = s.audit[len(s.audit)-maxAudit:]
	}
	if result != "ok" {
		log.Printf("read refused client=%q ref=%q result=%s", client, ref, result)
	} else {
		log.Printf("read ok client=%q ref=%q", client, ref)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------------------
// Admin web UI
// ---------------------------------------------------------------------------

func (s *server) adminAuth(w http.ResponseWriter, r *http.Request) (*adminSession, bool) {
	if c, err := r.Cookie("broker_admin"); err == nil {
		s.mu.Lock()
		sess, ok := s.sessions[c.Value]
		s.mu.Unlock()
		if ok && time.Now().Before(sess.Expires) {
			return sess, true
		}
	}
	// Proxy-header path: a same-netns authenticating proxy (oauth2-proxy
	// sidecar) asserts the user in a header. Only loopback peers may use
	// it, and the dashboard gets a stable server-side session so its CSRF
	// tokens work unchanged. trustProxyHeader may name several headers
	// (comma-separated); the first one present wins. oauth2-proxy sends
	// the identity upstream as X-Forwarded-User (pass_user_headers) and
	// exposes X-Auth-Request-User only in auth-request mode, so accept
	// both.
	if s.trustProxyHeader != "" && isLoopbackRemote(r.RemoteAddr) {
		user := ""
		for _, h := range strings.Split(s.trustProxyHeader, ",") {
			if v := r.Header.Get(strings.TrimSpace(h)); v != "" {
				user = v
				break
			}
		}
		if user != "" {
			key := "proxy:" + user
			s.mu.Lock()
			defer s.mu.Unlock()
			sess, ok := s.sessions[key]
			if !ok || time.Now().After(sess.Expires) {
				sess = &adminSession{CSRF: randHex(16), Expires: time.Now().Add(adminSessionTTL)}
				s.sessions[key] = sess
			}
			return sess, true
		}
	}
	return nil, false
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *server) checkCSRF(r *http.Request, sess *adminSession) bool {
	got := r.FormValue("csrf")
	return subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) == 1
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	got := sha256.Sum256([]byte(r.FormValue("admin_token")))
	if subtle.ConstantTimeCompare(got[:], s.adminTokenHash[:]) != 1 {
		http.Error(w, "invalid admin token", http.StatusUnauthorized)
		return
	}
	id := randHex(32)
	s.mu.Lock()
	s.sessions[id] = &adminSession{CSRF: randHex(16), Expires: time.Now().Add(adminSessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "broker_admin", Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(adminSessionTTL),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleUnlock(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cred := strings.TrimSpace(r.FormValue("credential"))
	if cred == "" {
		http.Error(w, "empty credential", http.StatusBadRequest)
		return
	}
	if err := s.backend.Verify(r.Context(), cred); err != nil {
		log.Printf("unlock failed: %v", err)
		http.Error(w, "credential verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.mu.Lock()
	s.credential = cred
	s.mu.Unlock()
	log.Printf("broker unlocked (credential held in memory only)")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleLock(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.credential = ""
	for _, g := range s.grants {
		g.Revoked = true
	}
	s.mu.Unlock()
	log.Printf("broker locked; all grants revoked")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleApprove(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := r.FormValue("request_id")
	var ttl time.Duration
	fmt.Sscanf(r.FormValue("ttl_seconds"), "%d", &ttl)
	ttl *= time.Second
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = time.Hour
	}
	reads := 100
	fmt.Sscanf(r.FormValue("max_reads"), "%d", &reads)
	if reads <= 0 || reads > 10000 {
		reads = 100
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(now)
	req, ok := s.requests[id]
	if !ok || req.Status != stPending {
		http.Error(w, "request not pending", http.StatusConflict)
		return
	}
	g := &grant{
		ID:         randHex(4),
		TicketHash: req.TicketHash,
		ClientName: req.ClientName,
		Scopes:     req.Scopes,
		ExpiresAt:  now.Add(ttl),
		ReadsLeft:  reads,
	}
	req.Status = stApproved
	req.GrantID = g.ID
	s.grants[g.ID] = g
	s.grantByTkt[g.TicketHash] = g
	log.Printf("approved request %s client=%q ttl=%s reads=%d", req.ID, req.ClientName, ttl, reads)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleDeny(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if req, ok := s.requests[r.FormValue("request_id")]; ok && req.Status == stPending {
		req.Status = stDenied
		log.Printf("denied request %s", req.ID)
	}
	s.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request, sess *adminSession) {
	if r.Method != http.MethodPost || !s.checkCSRF(r, sess) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if g, ok := s.grants[r.FormValue("grant_id")]; ok {
		g.Revoked = true
		log.Printf("revoked grant %s client=%q", g.ID, g.ClientName)
	}
	s.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- dashboard rendering ---

var dashTmpl = template.Must(template.New("dash").Parse(`<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>op-broker</title>
<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4em;text-align:left;vertical-align:top}
code{font-size:.9em}.locked{color:#b00;font-weight:bold}.open{color:#070;font-weight:bold}
input,select,textarea{font-size:1em} .small{color:#666;font-size:.85em}</style></head><body>
<h1>op-broker</h1>
<p>状態: {{if .Unlocked}}<span class="open">UNLOCKED（資格情報はメモリ内のみ）</span>{{else}}<span class="locked">LOCKED（何も読めません）</span>{{end}}
{{if .Demo}}<br><span class="small">DEMO モード: ダミーの秘密を返します</span>{{end}}</p>

{{if .Unlocked}}
<form method="post" action="/lock"><input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">ロックする（全 grant も失効）</button></form>
{{else}}
<form method="post" action="/unlock"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>1Password Service Account token（ops_...）を貼り付け — サーバーのメモリにだけ保持され、ディスクには書きません<br>
<input type="password" name="credential" size="70" autocomplete="off"></label>
<button type="submit">Unlock</button></form>
{{end}}

<h2>承認待ちリクエスト</h2>
{{if .Pending}}
<table><tr><th>コード</th><th>クライアント</th><th>scope / 理由</th><th>申請TTL</th><th>承認</th></tr>
{{range .Pending}}<tr>
<td><b style="font-size:1.3em">{{.Code}}</b><br><span class="small">{{.ID}}</span></td>
<td>{{.ClientName}}<br><span class="small">{{.Host}}</span></td>
<td>{{range .Scopes}}<code>{{.}}</code><br>{{end}}<span class="small">{{.Reason}}</span></td>
<td>{{.RequestedTTL}}</td>
<td><form method="post" action="/approve"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="request_id" value="{{.ID}}">
<select name="ttl_seconds"><option value="900">15分</option><option value="3600" selected>1時間</option><option value="28800">8時間</option><option value="86400">24時間</option></select>
<input type="number" name="max_reads" value="100" min="1" max="10000" style="width:5em">回
<button type="submit">承認</button></form>
<form method="post" action="/deny"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="request_id" value="{{.ID}}"><button type="submit">拒否</button></form></td>
</tr>{{end}}</table>
<p class="small">コードはクライアント側に表示される6桁と一致することを確認してから承認してください。</p>
{{else}}<p>なし</p>{{end}}

<h2>有効な grant</h2>
{{if .Grants}}
<table><tr><th>クライアント</th><th>scope</th><th>期限</th><th>残り読取</th><th></th></tr>
{{range .Grants}}<tr><td>{{.ClientName}}</td><td>{{range .Scopes}}<code>{{.}}</code><br>{{end}}</td>
<td>{{.ExpiresAt.Format "15:04:05"}}</td><td>{{.ReadsLeft}}</td>
<td><form method="post" action="/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="grant_id" value="{{.ID}}"><button type="submit">失効</button></form></td></tr>{{end}}</table>
{{else}}<p>なし</p>{{end}}

<h2>監査ログ（メモリ内・直近のみ）</h2>
{{if .Audit}}<table><tr><th>時刻</th><th>クライアント</th><th>ref</th><th>結果</th></tr>
{{range .Audit}}<tr><td>{{.At.Format "15:04:05"}}</td><td>{{.Client}}</td><td><code>{{.Ref}}</code></td><td>{{.Result}}</td></tr>{{end}}</table>
{{else}}<p>なし</p>{{end}}
</body></html>`))

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>op-broker login</title></head><body style="font-family:system-ui,sans-serif;max-width:480px;margin:3em auto">
<h1>op-broker</h1>
<form method="post" action="/login">
<label>Admin token（起動時に一度だけ表示されます）<br>
<input type="password" name="admin_token" size="40" autocomplete="off"></label>
<button type="submit">ログイン</button></form>
</body></html>`))

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminAuth(w, r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginTmpl.Execute(w, nil)
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.refreshLocked(now)
	data := map[string]any{
		"CSRF":     sess.CSRF,
		"Unlocked": s.credential != "",
		"Demo":     s.demo,
	}
	var pending []*accessRequest
	for _, req := range s.requests {
		if req.Status == stPending {
			pending = append(pending, req)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	data["Pending"] = pending
	var grants []*grant
	for _, g := range s.grants {
		if g.active(now) {
			grants = append(grants, g)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].ExpiresAt.Before(grants[j].ExpiresAt) })
	data["Grants"] = grants
	audit := make([]auditEntry, len(s.audit))
	copy(audit, s.audit)
	data["Audit"] = audit
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = dashTmpl.Execute(w, data)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		unlocked := s.credential != ""
		s.mu.Unlock()
		state := "locked"
		if unlocked {
			state = "unlocked"
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": state})
	})
	mux.HandleFunc("/api/requests", s.handleCreateRequest)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/read", s.handleRead)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/", s.handleDashboard)
	admin := func(h func(http.ResponseWriter, *http.Request, *adminSession)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sess, ok := s.adminAuth(w, r)
			if !ok {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			h(w, r, sess)
		}
	}
	mux.HandleFunc("/unlock", admin(s.handleUnlock))
	mux.HandleFunc("/lock", admin(s.handleLock))
	mux.HandleFunc("/approve", admin(s.handleApprove))
	mux.HandleFunc("/deny", admin(s.handleDeny))
	mux.HandleFunc("/revoke", admin(s.handleRevoke))
	return mux
}
