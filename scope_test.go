package main

import "testing"

func TestScopeMatching(t *testing.T) {
	cases := []struct {
		pattern, ref string
		want         bool
	}{
		// Exact field reference.
		{"op://Vault/Item/password", "op://Vault/Item/password", true},
		{"op://Vault/Item/password", "op://Vault/Item/username", false},
		// Whole item: all fields.
		{"op://Vault/Item", "op://Vault/Item/password", true},
		{"op://Vault/Item", "op://Vault/Item/notes/plain", true},
		{"op://Vault/Item", "op://Vault/Other/password", false},
		// Whole vault, both spellings.
		{"op://Vault", "op://Vault/Any/field", true},
		{"op://Vault/*", "op://Vault/Any/field", true},
		{"op://Vault", "op://Other/Any/field", false},
		// Everything.
		{"op://*", "op://AnyVault/AnyItem/field", true},
		// Segment awareness: no prefix spoofing.
		{"op://Vault", "op://VaultEvil/Item/field", false},
		{"op://Vault/Item", "op://Vault/Item2/field", false},
		{"op://Va", "op://Vault/Item/field", false},
		// A query suffix changes rendering, not identity: the field-scope
		// covers the OTP rendering of the same field.
		{"op://Vault/Item/one-time password", "op://Vault/Item/one-time password?attribute=otp", true},
		{"op://Vault/Item/one-time password", "op://Vault/Item/password?attribute=otp", false},
		{"op://Vault/Item", "op://Vault/Item/one-time password?attribute=otp", true},
	}
	for _, c := range cases {
		if got := scopeMatches([]string{c.pattern}, c.ref); got != c.want {
			t.Errorf("scopeMatches(%q, %q) = %v, want %v", c.pattern, c.ref, got, c.want)
		}
	}
}

func TestValidScopePatterns(t *testing.T) {
	valid := []string{
		"op://Vault/Item/field",
		"op://Vault/Item",
		"op://Vault",
		"op://Vault/*",
		"op://Vault/Item/*",
		"op://*",
	}
	for _, sc := range valid {
		if !validScope(sc) {
			t.Errorf("validScope(%q) = false, want true", sc)
		}
	}
	invalid := []string{
		"",
		"Vault/Item/field",
		"op://",
		"op://Vault//field",
		"op://*/Item/field", // wildcard only allowed last
		"op://Vault/*/field",
	}
	for _, sc := range invalid {
		if validScope(sc) {
			t.Errorf("validScope(%q) = true, want false", sc)
		}
	}
}
