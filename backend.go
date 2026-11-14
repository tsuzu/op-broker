package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// FieldInfo is metadata about one item field: section, label and type,
// plus the secret references a client can use to read it. It never
// carries a value — for OTP fields it deliberately omits the seed, so a
// describe response is safe to show to the requesting client.
type FieldInfo struct {
	Section  string `json:"section,omitempty"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	ID       string `json:"id,omitempty"`
	Ref      string `json:"ref"`
	OTPRef   string `json:"otp_ref,omitempty"`
	OTPIDRef string `json:"otp_id_ref,omitempty"`
}

// Backend abstracts where secrets actually come from. The server holds the
// backend credential (e.g. a 1Password Service Account token) in memory only
// and hands it to the backend per call; the backend must not persist it.
type Backend interface {
	// Verify checks that the credential works at all (called at unlock time).
	Verify(ctx context.Context, credential string) error
	// Read resolves one secret reference like op://Vault/Item/field.
	Read(ctx context.Context, credential, ref string) (string, error)
	// Describe returns the field structure (metadata only, never values)
	// of one item, so clients can construct exact references.
	Describe(ctx context.Context, credential, vault, item string) ([]FieldInfo, error)
}

// OpBackend shells out to the 1Password CLI with the Service Account token
// passed via the child process environment only. Nothing is written to disk
// by this process; op itself is invoked per read, with no session config.
type OpBackend struct {
	OpPath string // path to the op binary (default "op")
}

func (b *OpBackend) run(ctx context.Context, credential string, args ...string) (string, error) {
	op := b.OpPath
	if op == "" {
		op = "op"
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, op, args...)
	// Environment: inherit, but force non-interactive SA mode and scrub any
	// ambient op session variables that could confuse the call.
	env := []string{}
	for _, e := range cmd.Environ() {
		if strings.HasPrefix(e, "OP_SESSION") || strings.HasPrefix(e, "OP_SERVICE_ACCOUNT_TOKEN=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env,
		"OP_SERVICE_ACCOUNT_TOKEN="+credential,
		"OP_BIOMETRIC_UNLOCK_ENABLED=false",
		"OP_FORMAT=json",
	)
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("op %s: %s", strings.Join(args[:min(2, len(args))], " "), msg)
	}
	return string(out), nil
}

func (b *OpBackend) Verify(ctx context.Context, credential string) error {
	if !strings.HasPrefix(credential, "ops_") {
		return errors.New("credential does not look like a Service Account token (expected ops_ prefix)")
	}
	_, err := b.run(ctx, credential, "vault", "list")
	return err
}

func (b *OpBackend) Read(ctx context.Context, credential, ref string) (string, error) {
	out, err := b.run(ctx, credential, "read", "--no-color", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\n"), nil
}

func (b *OpBackend) Describe(ctx context.Context, credential, vault, item string) ([]FieldInfo, error) {
	out, err := b.run(ctx, credential, "item", "get", item, "--vault", vault, "--format", "json")
	if err != nil {
		return nil, err
	}
	return parseOpItemFields(vault, item, []byte(out))
}

// parseOpItemFields extracts ONLY metadata (section, label, type) from
// `op item get --format json` output. Values present in the JSON —
// including TOTP seeds — are dropped here and never leave the backend.
func parseOpItemFields(vault, item string, data []byte) ([]FieldInfo, error) {
	var parsed struct {
		Fields []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Label   string `json:"label"`
			Section *struct {
				Label string `json:"label"`
			} `json:"section"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse op item output: %w", err)
	}
	fields := make([]FieldInfo, 0, len(parsed.Fields))
	for _, f := range parsed.Fields {
		fi := FieldInfo{Label: f.Label, Type: f.Type, ID: f.ID}
		ref := "op://" + vault + "/" + item + "/"
		if f.Section != nil && f.Section.Label != "" {
			fi.Section = f.Section.Label
			ref += f.Section.Label + "/"
		}
		ref += f.Label
		fi.Ref = ref
		if f.Type == "OTP" {
			fi.OTPRef = ref + "?attribute=otp"
			// When two fields share one label, the label reference is
			// ambiguous and op refuses it; the id reference always works.
			if f.ID != "" {
				fi.OTPIDRef = "op://" + vault + "/" + item + "/" + f.ID + "?attribute=otp"
			}
		}
		fields = append(fields, fi)
	}
	return fields, nil
}

// MockBackend is for tests and for a demo deployment without a real
// 1Password account attached. It serves a tiny fixed set of fake secrets.
type MockBackend struct {
	Secrets map[string]string
}

func (b *MockBackend) Verify(_ context.Context, credential string) error {
	if len(credential) < 4 {
		return errors.New("demo credential too short")
	}
	return nil
}

func (b *MockBackend) Read(_ context.Context, _, ref string) (string, error) {
	v, ok := b.Secrets[ref]
	if !ok {
		return "", fmt.Errorf("no such secret in demo backend: %s", ref)
	}
	return v, nil
}

func (b *MockBackend) Describe(_ context.Context, _, vault, item string) ([]FieldInfo, error) {
	itemRef := "op://" + vault + "/" + item
	seen := map[string]bool{}
	var fields []FieldInfo
	for ref := range b.Secrets {
		if !strings.HasPrefix(ref, itemRef+"/") {
			continue
		}
		label := strings.TrimPrefix(ref, itemRef+"/")
		if strings.Contains(label, "/") || seen[label] {
			continue
		}
		seen[label] = true
		fields = append(fields, FieldInfo{Label: label, Type: "STRING", Ref: ref})
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("no such item in demo backend: %s", itemRef)
	}
	if item == "demo" {
		fields = append(fields, FieldInfo{
			Label: "one-time password", Type: "OTP",
			Ref: itemRef + "/one-time password", OTPRef: itemRef + "/one-time password?attribute=otp",
		})
	}
	return fields, nil
}

func defaultMockBackend() *MockBackend {
	return &MockBackend{Secrets: map[string]string{
		"op://Automation/demo/password":     "demo-password-value",
		"op://Automation/demo/api-key":      "demo-api-key-12345",
		"op://Automation/deploy/privatekey": "-----BEGIN OPENSSH PRIVATE KEY-----\ndemo-key-material\n-----END OPENSSH PRIVATE KEY-----",
	}}
}
