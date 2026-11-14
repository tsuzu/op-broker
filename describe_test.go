package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func doDescribe(base, ticket, ref string) (int, []FieldInfo, string) {
	body, _ := json.Marshal(map[string]string{"ref": ref})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/describe", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer resp.Body.Close()
	var out struct {
		Fields []FieldInfo `json:"fields"`
		Error  string      `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Fields, out.Error
}

func TestDescribeFlow(t *testing.T) {
	base, _ := newTestServer(t)
	admin := adminClient(t, base)

	// Locked: describe is refused with 423 even with a valid ticket.
	ticket := mkTicket(t)
	reqID, _ := createRequest(t, base, ticket, []string{"op://Automation"})
	approve(t, admin, base, reqID, "3600")
	if code, _, _ := doDescribe(base, ticket, "op://Automation/demo"); code != http.StatusLocked {
		t.Fatalf("locked describe status %d, want 423", code)
	}

	unlock(t, admin, base)
	code, fields, errStr := doDescribe(base, ticket, "op://Automation/demo")
	if code != http.StatusOK {
		t.Fatalf("describe status %d: %s", code, errStr)
	}
	var otp *FieldInfo
	labels := map[string]bool{}
	for i, f := range fields {
		labels[f.Label] = true
		if f.Type == "OTP" {
			otp = &fields[i]
		}
	}
	if !labels["password"] || !labels["api-key"] {
		t.Fatalf("expected demo fields password+api-key, got %+v", fields)
	}
	if otp == nil {
		t.Fatalf("expected an OTP field, got %+v", fields)
	}
	if otp.OTPRef != "op://Automation/demo/one-time password?attribute=otp" {
		t.Fatalf("otp_ref = %q", otp.OTPRef)
	}

	// A field-level scope does NOT authorize describing the whole item.
	ticket2 := mkTicket(t)
	reqID2, _ := createRequest(t, base, ticket2, []string{"op://Automation/demo/password"})
	approve(t, admin, base, reqID2, "3600")
	if code, _, _ := doDescribe(base, ticket2, "op://Automation/demo"); code != http.StatusForbidden {
		t.Fatalf("field-scope describe status %d, want 403", code)
	}

	// Unknown item: backend error surfaces as 502.
	if code, _, _ := doDescribe(base, ticket, "op://Automation/nope"); code != http.StatusBadGateway {
		t.Fatalf("unknown item describe status %d, want 502", code)
	}

	// Malformed refs are rejected.
	if code, _, _ := doDescribe(base, ticket, "op://Automation/demo/password"); code != http.StatusBadRequest {
		t.Fatalf("field ref describe status %d, want 400", code)
	}
}

func TestParseOpItemFieldsDropsValues(t *testing.T) {
	// Shaped like real `op item get --format json` output, including a
	// TOTP seed and a password value: neither may survive parsing.
	data := []byte(`{
	  "id": "abc", "title": "SMMR stg",
	  "fields": [
	    {"id": "f1", "type": "STRING", "label": "username", "value": "someone@example.com"},
	    {"id": "f2", "type": "CONCEALED", "label": "password", "value": "p@ssw0rd"},
	    {"id": "TOTP_abc123", "type": "OTP", "label": "totp-code", "value": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
	     "section": {"id": "s1", "label": "MFA"}}
	  ]
	}`)
	fields, err := parseOpItemFields("milldea", "SMMR stg", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("got %d fields, want 3", len(fields))
	}
	blob, _ := json.Marshal(fields)
	for _, leak := range []string{"p@ssw0rd", "JBSWY3DPEHPK3PXP", "someone@example.com", "otpauth"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("describe output leaked %q: %s", leak, blob)
		}
	}
	otp := fields[2]
	if otp.Section != "MFA" || otp.Ref != "op://milldea/SMMR stg/MFA/totp-code" {
		t.Fatalf("otp field = %+v", otp)
	}
	if otp.OTPRef != "op://milldea/SMMR stg/MFA/totp-code?attribute=otp" {
		t.Fatalf("otp_ref = %q", otp.OTPRef)
	}
	if otp.ID != "TOTP_abc123" || otp.OTPIDRef != "op://milldea/SMMR stg/TOTP_abc123?attribute=otp" {
		t.Fatalf("otp id refs = %+v", otp)
	}
	if fields[0].Ref != "op://milldea/SMMR stg/username" {
		t.Fatalf("username ref = %q", fields[0].Ref)
	}
}
