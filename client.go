package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// The client side of the ticket model: a ticket is a random bearer string
// generated per request and kept only in memory — either in the shell
// environment (eval mode) or in the local agent daemon (agent.go). It is
// never written to disk and never put in a keychain. The server only ever
// sees its SHA-256 hash at request time; the human approval on the web
// dashboard is what turns the ticket into a time-boxed read grant.

func newTicket() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type client struct {
	base   string
	http   *http.Client
	ticket string
}

func newClient(base, ticket string) *client {
	return &client{
		base:   strings.TrimRight(base, "/"),
		http:   &http.Client{Timeout: 35 * time.Second},
		ticket: ticket,
	}
}

func (c *client) doJSON(method, path string, body any, auth bool) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.ticket)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, err
}

type statusResp struct {
	Status       string   `json:"status"`
	RequestID    string   `json:"request_id"`
	GrantExpires string   `json:"grant_expires_at"`
	ReadsLeft    int      `json:"reads_left"`
	Scopes       []string `json:"scopes"`
	Error        string   `json:"error"`
}

func (c *client) status() (*statusResp, int, error) {
	code, data, err := c.doJSON(http.MethodGet, "/api/status", nil, true)
	if err != nil {
		return nil, code, err
	}
	var st statusResp
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, code, fmt.Errorf("bad status response: %s", data)
	}
	return &st, code, nil
}

// cmdRequest implements: opbroker request --server URL [--name N] [--reason R]
// [--ttl 1h] [--wait 10m] [--agent] op://... [op://...]
// With --agent, the approved ticket is handed to the local agent daemon
// instead of being printed as an export line: no shell or tool ever has to
// carry the ticket itself.
// grantCoversAll reports whether a held grant's scopes cover every
// requested scope.
func grantCoversAll(held, want []string) bool {
	for _, w := range want {
		if !scopeMatches(held, w) {
			return false
		}
	}
	return true
}

// reusableGrant looks for an agent-held grant that already covers the
// requested scopes with at least minRemaining of lifetime left.
func reusableGrant(want []string, minRemaining time.Duration) (agentEntryInfo, bool) {
	for _, e := range agentList() {
		if e.ExpiresUnix == 0 {
			continue
		}
		if time.Until(time.Unix(e.ExpiresUnix, 0)) < minRemaining {
			continue
		}
		if grantCoversAll(e.Scopes, want) {
			return e, true
		}
	}
	return agentEntryInfo{}, false
}

func cmdRequest(args []string) error {
	var server, name, reason string
	var ttl, wait time.Duration = time.Hour, 10 * time.Minute
	var minRemaining time.Duration = time.Hour
	var scopes []string
	useAgent := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			server = args[i]
		case "--name":
			i++
			name = args[i]
		case "--agent":
			useAgent = true
		case "--reason":
			i++
			reason = args[i]
		case "--ttl":
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			ttl = d
		case "--wait":
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			wait = d
		case "--min-remaining":
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			minRemaining = d
		default:
			scopes = append(scopes, args[i])
		}
	}
	if server == "" {
		return fmt.Errorf("--server is required (or set BROKER_SERVER)")
	}
	if len(scopes) == 0 {
		return fmt.Errorf("at least one op:// scope is required")
	}
	// Scripts often fire the same request repeatedly. In agent mode,
	// if a held grant already covers the scopes with enough lifetime
	// left (default 1h), succeed immediately without creating a new
	// request — no dashboard noise, no push notification.
	if useAgent && minRemaining > 0 {
		if e, ok := reusableGrant(scopes, minRemaining); ok {
			exp := time.Unix(e.ExpiresUnix, 0)
			fmt.Fprintf(os.Stderr, "既に有効な grant があります（期限 %s、残り %s）。新規リクエストは出しませんでした。\n",
				exp.Format("2006-01-02 15:04:05"), time.Until(exp).Round(time.Minute))
			return nil
		}
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	host, _ := os.Hostname()
	ticket, err := newTicket()
	if err != nil {
		return err
	}
	c := newClient(server, ticket)
	code, data, err := c.doJSON(http.MethodPost, "/api/requests", map[string]any{
		"ticket_hash": ticketHash(ticket),
		"client_name": name,
		"host":        host,
		"reason":      reason,
		"scopes":      scopes,
		"ttl_seconds": int(ttl.Seconds()),
	}, false)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return fmt.Errorf("request failed (%d): %s", code, data)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	// The eval-able line goes to stdout; everything human-facing to stderr.
	// In agent mode nothing secret is printed at all.
	if !useAgent {
		fmt.Printf("export BROKER_TICKET=%s\n", ticket)
	}
	fmt.Fprintf(os.Stderr, "request %s created\n", resp.RequestID)
	fmt.Fprintf(os.Stderr, "\n  確認コード: %s\n\n", resp.Code)
	fmt.Fprintf(os.Stderr, "ダッシュボードでこのコードを承認してください。承認を待ちます（最大 %s）...\n", wait)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		st, _, err := c.status()
		if err == nil {
			switch st.Status {
			case "approved":
				if useAgent {
					exp, perr := time.Parse(time.RFC3339, st.GrantExpires)
					if perr != nil {
						exp = time.Now().Add(ttl)
					}
					if err := storeToAgent(ticket, st.Scopes, exp); err != nil {
						return fmt.Errorf("approved, but handing the ticket to the local agent failed: %w", err)
					}
					fmt.Fprintf(os.Stderr, "承認されました。有効期限: %s（残り読取 %d 回）\nチケットはローカルエージェントに預けました。以後の `opbroker read` / `opbroker status` はそのまま使えます。\n", st.GrantExpires, st.ReadsLeft)
					return nil
				}
				fmt.Fprintf(os.Stderr, "承認されました。有効期限: %s（残り読取 %d 回）\n", st.GrantExpires, st.ReadsLeft)
				return nil
			case "denied":
				return fmt.Errorf("request was denied")
			case "expired":
				return fmt.Errorf("request expired before approval")
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for approval (request stays pending briefly; re-run request if needed)")
}

// cmdRead implements: opbroker read --server URL op://Vault/Item/field
// The ticket comes from $BROKER_TICKET. The secret is printed to stdout.
func cmdRead(args []string) error {
	var server, ref string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			server = args[i]
		default:
			ref = args[i]
		}
	}
	if server == "" {
		server = os.Getenv("BROKER_SERVER")
	}
	if ref == "" {
		return fmt.Errorf("a secret reference op://Vault/Item/field is required")
	}
	ticket, _ := resolveTicketForRef(ref)
	if ticket == "" {
		return fmt.Errorf("no ticket covers %s: set BROKER_TICKET or run `opbroker request --agent ...` first", ref)
	}
	c := newClient(server, ticket)
	code, data, err := c.doJSON(http.MethodPost, "/api/read", map[string]string{"ref": ref}, true)
	if err != nil {
		return err
	}
	var resp struct {
		Value string `json:"value"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("bad read response: %s", data)
	}
	if code != http.StatusOK {
		return fmt.Errorf("read refused (%d): %s", code, resp.Error)
	}
	fmt.Println(resp.Value)
	return nil
}

// cmdDescribe implements: opbroker describe [--server URL] op://Vault/Item
// It prints the item's field structure (metadata only) with the exact
// references to use with `opbroker read`.
func cmdDescribe(args []string) error {
	server := os.Getenv("BROKER_SERVER")
	var ref string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			server = args[i]
		default:
			ref = args[i]
		}
	}
	if ref == "" {
		return fmt.Errorf("an item reference op://Vault/Item is required")
	}
	ticket, _ := resolveTicketForRef(ref)
	if ticket == "" {
		return fmt.Errorf("no ticket covers %s: set BROKER_TICKET or run `opbroker request --agent ...` first", ref)
	}
	c := newClient(server, ticket)
	code, data, err := c.doJSON(http.MethodPost, "/api/describe", map[string]string{"ref": ref}, true)
	if err != nil {
		return err
	}
	var resp struct {
		Vault  string      `json:"vault"`
		Item   string      `json:"item"`
		Fields []FieldInfo `json:"fields"`
		Error  string      `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("bad describe response: %s", data)
	}
	if code != http.StatusOK {
		return fmt.Errorf("describe refused (%d): %s", code, resp.Error)
	}
	for _, f := range resp.Fields {
		fmt.Println(f.Ref)
		meta := "  type: " + f.Type
		if f.Section != "" {
			meta += ", section: " + f.Section
		}
		if f.ID != "" {
			meta += ", id: " + f.ID
		}
		fmt.Println(meta)
		if f.OTPRef != "" {
			fmt.Printf("  current code: opbroker read %q\n", f.OTPRef)
		}
		if f.OTPIDRef != "" {
			fmt.Printf("  current code (by id, for duplicate labels): opbroker read %q\n", f.OTPIDRef)
		}
	}
	return nil
}

// cmdStatus implements: opbroker status --server URL
// With $BROKER_TICKET it reports that grant; otherwise it reports
// every grant the local agent holds.
func cmdStatus(args []string) error {
	server := os.Getenv("BROKER_SERVER")
	for i := 0; i < len(args); i++ {
		if args[i] == "--server" {
			i++
			server = args[i]
		}
	}
	printStatus := func(ticket string) error {
		c := newClient(server, ticket)
		st, code, err := c.status()
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("status failed (%d): %s", code, st.Error)
		}
		fmt.Printf("status: %s\n", st.Status)
		if st.GrantExpires != "" {
			fmt.Printf("grant_expires_at: %s\nreads_left: %d\nscopes: %s\n", st.GrantExpires, st.ReadsLeft, strings.Join(st.Scopes, ", "))
		}
		return nil
	}
	if t := os.Getenv("BROKER_TICKET"); t != "" {
		return printStatus(t)
	}
	tickets := agentTickets()
	if len(tickets) == 0 {
		return fmt.Errorf("no ticket: set BROKER_TICKET or run `opbroker request --agent ...` first")
	}
	for i, t := range tickets {
		if i > 0 {
			fmt.Println("---")
		}
		if err := printStatus(t); err != nil {
			return err
		}
	}
	return nil
}

// cmdRenew implements: opbroker renew [--server URL] [--ttl 1h]
// [--wait 10m] [op://scope-or-ref]
// It asks the owner to extend the lifetime of an existing grant —
// the same ticket keeps working; no new ticket is issued. The target
// grant is chosen by $BROKER_TICKET, by the agent entry covering the
// given reference, or by the agent's only entry. Approval is required
// exactly as for a fresh request (dashboard + push notification).
func cmdRenew(args []string) error {
	var server, target string
	var ttl, wait time.Duration = time.Hour, 10 * time.Minute
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			server = args[i]
		case "--ttl":
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			ttl = d
		case "--wait":
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return err
			}
			wait = d
		default:
			target = args[i]
		}
	}
	if server == "" {
		server = os.Getenv("BROKER_SERVER")
	}
	var ticket string
	fromAgent := false
	if t := os.Getenv("BROKER_TICKET"); t != "" {
		ticket = t
	} else if target != "" {
		ticket, fromAgent = resolveTicketForRef(target)
		if ticket == "" {
			return fmt.Errorf("the agent holds no grant covering %s", target)
		}
	} else if infos := agentList(); len(infos) == 1 {
		ticket = agentResolve("")
		fromAgent = ticket != ""
	} else if len(infos) == 0 {
		return fmt.Errorf("no grant to renew: run `opbroker request --agent ...` first")
	} else {
		return fmt.Errorf("the agent holds %d grants; name the one to renew by a scope it covers, e.g. `opbroker renew op://Vault`", len(infos))
	}
	if ticket == "" {
		return fmt.Errorf("could not resolve a ticket to renew")
	}
	c := newClient(server, ticket)
	before, _, err := c.status()
	if err != nil {
		return err
	}
	oldExpiry := before.GrantExpires
	code, data, err := c.doJSON(http.MethodPost, "/api/renew", map[string]any{"ttl_seconds": int(ttl.Seconds())}, true)
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return fmt.Errorf("renew failed (%d): %s", code, data)
	}
	var resp struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "renewal %s created for scopes %s\n", resp.RequestID, strings.Join(before.Scopes, ", "))
	fmt.Fprintf(os.Stderr, "\n  確認コード: %s\n\n", resp.Code)
	fmt.Fprintf(os.Stderr, "ダッシュボードでこのコードを承認してください。承認を待ちます（最大 %s）...\n", wait)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		st, _, err := c.status()
		if err == nil {
			if st.Status == "denied" {
				return fmt.Errorf("renewal was denied")
			}
			if st.GrantExpires != "" && st.GrantExpires != oldExpiry {
				if exp, perr := time.Parse(time.RFC3339, st.GrantExpires); perr == nil && time.Now().Before(exp) {
					if fromAgent {
						_ = storeToAgent(ticket, st.Scopes, exp) // refresh the entry's expiry
					}
					fmt.Fprintf(os.Stderr, "更新されました。新しい有効期限: %s（残り読取 %d 回）\n", st.GrantExpires, st.ReadsLeft)
					return nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for renewal approval")
}
