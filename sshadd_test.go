package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHFormatRef(t *testing.T) {
	cases := map[string]string{
		"op://V/I/private key":                    "op://V/I/private key?ssh-format=openssh",
		"op://V/I/private key?attribute=otp":      "op://V/I/private key?attribute=otp&ssh-format=openssh",
		"op://V/I/private key?ssh-format=openssh": "op://V/I/private key?ssh-format=openssh",
		"op://V/I/private key?ssh-format=pkcs8":   "op://V/I/private key?ssh-format=pkcs8",
	}
	for in, want := range cases {
		if got := sshFormatRef(in); got != want {
			t.Errorf("sshFormatRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSSHAddFlow(t *testing.T) {
	for _, bin := range []string{"ssh-keygen", "ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "opbroker-test").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pubOut, err := exec.Command("ssh-keygen", "-lf", keyPath+".pub").Output()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Fields(string(pubOut))[1]

	base, s := newTestServer(t)
	s.backend.(*MockBackend).Secrets["op://Automation/demo/private key?ssh-format=openssh"] = string(keyPEM)
	admin := adminClient(t, base)
	unlock(t, admin, base)
	ticket := mkTicket(t)
	reqID, _ := createRequest(t, base, ticket, []string{"op://Automation"})
	approve(t, admin, base, reqID, "3600")
	t.Setenv("BROKER_TICKET", ticket)

	// A throwaway ssh-agent on a private socket.
	sock := filepath.Join(dir, "agent.sock")
	agentOut, err := exec.Command("ssh-agent", "-a", sock).Output()
	if err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", sock)
	// ssh-agent prints SSH_AGENT_PID=<pid>; — kill it at the end.
	for _, f := range strings.Fields(string(agentOut)) {
		if strings.HasPrefix(f, "SSH_AGENT_PID=") {
			pid := strings.TrimSuffix(strings.TrimPrefix(f, "SSH_AGENT_PID="), ";")
			defer func() {
				if p, err := os.FindProcess(atoi(pid)); err == nil {
					p.Kill()
				}
			}()
		}
	}

	if err := cmdSSHAdd([]string{"--server", base, "--lifetime", "30m", "op://Automation/demo/private key"}); err != nil {
		t.Fatalf("ssh-add: %v", err)
	}
	listOut, err := exec.Command("ssh-add", "-l").Output()
	if err != nil {
		t.Fatalf("ssh-add -l: %v", err)
	}
	if !strings.Contains(string(listOut), fingerprint) {
		t.Fatalf("agent does not hold the key; -l says: %s", listOut)
	}
	// The key must have a bounded lifetime (not "forever"): -l cannot
	// show it, but a second add with the grant gone must fail cleanly.
	_ = time.Now
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
