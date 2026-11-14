package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// opbroker is an approval-gated secrets broker in front of 1Password.
//
//   - The server holds a 1Password Service Account token in memory only,
//     registered by the owner through the web dashboard ("unlock"). Nothing
//     is ever written to disk; a restart returns the server to locked.
//   - Clients generate an ephemeral ticket, ask for a scoped read grant, and
//     a human approves (or denies) the request on the dashboard after
//     checking a 6-digit pairing code. Only while the grant is valid can the
//     ticket read the approved op:// references.
//   - Client tickets are plain bearer strings kept in the shell environment
//     on purpose: the web approval is the authentication, the ticket is only
//     the claim ticket that binds reads to the approved request.
func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "request":
		err = cmdRequest(prependServerEnv(os.Args[2:]))
	case "read":
		err = cmdRead(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// prependServerEnv lets BROKER_SERVER stand in for --server on request.
func prependServerEnv(args []string) []string {
	for _, a := range args {
		if a == "--server" {
			return args
		}
	}
	if s := os.Getenv("BROKER_SERVER"); s != "" {
		return append([]string{"--server", s}, args...)
	}
	return args
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":18787", "listen address (bind to private interfaces only: Tailscale/WireGuard/LAN)")
	opPath := fs.String("op", "op", "path to the 1Password CLI binary")
	demo := fs.Bool("demo", false, "serve demo secrets instead of real 1Password items (for testing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var backend Backend
	if *demo {
		backend = defaultMockBackend()
	} else {
		backend = &OpBackend{OpPath: *opPath}
	}
	adminToken := os.Getenv("BROKER_ADMIN_TOKEN")
	generated := false
	if adminToken == "" {
		adminToken = randHex(24)
		generated = true
	}
	s := newServer(backend, *demo, adminToken)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("op-broker listening on %s (demo=%v)", *listen, *demo)
	if generated {
		// Shown exactly once, at startup, in the server log. The token is
		// regenerated on every restart and never stored anywhere.
		log.Printf("ADMIN TOKEN (this boot only): %s", adminToken)
	}
	log.Printf("dashboard: unlock + approvals are done in the web UI; server starts LOCKED")
	return srv.ListenAndServe()
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  opbroker serve   [--listen :18787] [--op /path/to/op] [--demo]
  opbroker request --server URL [--name N] [--reason R] [--ttl 1h] [--wait 10m] op://... [op://...]
  opbroker read    [--server URL] op://Vault/Item/field     (ticket from $BROKER_TICKET)
  opbroker status  [--server URL]                           (ticket from $BROKER_SERVER/$BROKER_TICKET)`)
}
