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
// generated per session and kept only in the shell environment (never on
// disk, never in a keychain). The server only ever sees its SHA-256 hash at
// request time; the human approval on the web dashboard is what turns the
// ticket into a time-boxed read grant.

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
// [--ttl 1h] [--wait 10m] op://... [op://...]
func cmdRequest(args []string) error {
	var server, name, reason string
	var ttl, wait time.Duration = time.Hour, 10 * time.Minute
	var scopes []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			i++
			server = args[i]
		case "--name":
			i++
			name = args[i]
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
	fmt.Printf("export BROKER_TICKET=%s\n", ticket)
	fmt.Fprintf(os.Stderr, "request %s created\n", resp.RequestID)
	fmt.Fprintf(os.Stderr, "\n  確認コード: %s\n\n", resp.Code)
	fmt.Fprintf(os.Stderr, "ダッシュボードでこのコードを承認してください。承認を待ちます（最大 %s）...\n", wait)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		st, _, err := c.status()
		if err == nil {
			switch st.Status {
			case "approved":
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
	ticket := os.Getenv("BROKER_TICKET")
	if ticket == "" {
		return fmt.Errorf("BROKER_TICKET is not set; run `eval $(opbroker request ...)` first")
	}
	if ref == "" {
		return fmt.Errorf("a secret reference op://Vault/Item/field is required")
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

// cmdStatus implements: opbroker status --server URL
func cmdStatus(args []string) error {
	server := os.Getenv("BROKER_SERVER")
	for i := 0; i < len(args); i++ {
		if args[i] == "--server" {
			i++
			server = args[i]
		}
	}
	ticket := os.Getenv("BROKER_TICKET")
	if ticket == "" {
		return fmt.Errorf("BROKER_TICKET is not set")
	}
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
