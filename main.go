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
	case "describe":
		err = cmdDescribe(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "renew":
		err = cmdRenew(os.Args[2:])
	case "agent":
		err = cmdAgent(os.Args[2:])
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
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (PEM); with --tls-key, serve HTTPS with hot reload on file change")
	tlsKey := fs.String("tls-key", "", "TLS private key file (PEM)")
	trustProxyHeader := fs.String("trust-proxy-header", "", "comma-separated headers set by a loopback authenticating proxy (e.g. X-Forwarded-User,X-Auth-Request-User); loopback requests carrying one are admin-authenticated")
	firebaseConfig := fs.String("firebase-config", "", "path to Firebase web config JSON (with vapidKey); with --fcm-credentials, enables PWA push notifications on new requests")
	fcmCredentials := fs.String("fcm-credentials", "", "path to a Google service account JSON used to send FCM messages")
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
	s.trustProxyHeader = *trustProxyHeader
	if (*firebaseConfig == "") != (*fcmCredentials == "") {
		return fmt.Errorf("--firebase-config and --fcm-credentials must be given together")
	}
	if *firebaseConfig != "" {
		cfgData, err := os.ReadFile(*firebaseConfig)
		if err != nil {
			return fmt.Errorf("firebase config: %w", err)
		}
		cfg, err := loadFirebaseConfig(cfgData)
		if err != nil {
			return err
		}
		saData, err := os.ReadFile(*fcmCredentials)
		if err != nil {
			return fmt.Errorf("fcm credentials: %w", err)
		}
		fc, err := newFCMClient(saData)
		if err != nil {
			return err
		}
		if fc.project != cfg.ProjectID {
			return fmt.Errorf("firebase project mismatch: config %q vs service account %q", cfg.ProjectID, fc.project)
		}
		s.firebaseCfg = cfg
		s.fcm = fc
		log.Printf("push notifications enabled (firebase project %s)", cfg.ProjectID)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if generated {
		// Shown exactly once, at startup, in the server log. The token is
		// regenerated on every restart and never stored anywhere.
		log.Printf("ADMIN TOKEN (this boot only): %s", adminToken)
	}
	log.Printf("dashboard: unlock + approvals are done in the web UI; server starts LOCKED")
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must be given together")
	}
	if *tlsCert != "" {
		rl, err := newCertReloader(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		srv.TLSConfig = rl.tlsConfig()
		log.Printf("op-broker listening on %s (demo=%v, https with cert reload)", *listen, *demo)
		return srv.ListenAndServeTLS("", "")
	}
	log.Printf("op-broker listening on %s (demo=%v, http)", *listen, *demo)
	return srv.ListenAndServe()
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  opbroker serve   [--listen :18787] [--op /path/to/op] [--demo]
  opbroker request --server URL [--name N] [--reason R] [--ttl 1h] [--wait 10m] [--agent] op://... [op://...]
  opbroker read    [--server URL] op://Vault/Item/field     (ticket from $BROKER_TICKET or the local agent)
  opbroker describe [--server URL] op://Vault/Item          (field structure, metadata only)
  opbroker status  [--server URL]                           (ticket from $BROKER_TICKET or the local agent)
  opbroker renew   [--server URL] [--ttl 1h] [--wait 10m] [op://scope]   (extend a grant's life; owner approval required)
  opbroker agent   [--stop|--forget|--list]                 (local ticket daemon; started automatically by request --agent)`)
}
