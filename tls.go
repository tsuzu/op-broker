package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// certReloader serves a TLS key pair from files and transparently picks up
// replacements (cert-manager renewals rewrite the Secret volume) without a
// process restart. The pair is reloaded lazily when a file's mtime changes.
type certReloader struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	loadedAt time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() (*tls.Certificate, error) {
	crt, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, err
	}
	ci, _ := os.Stat(r.certFile)
	ki, _ := os.Stat(r.keyFile)
	r.cert = &crt
	if ci != nil {
		r.certMod = ci.ModTime()
	}
	if ki != nil {
		r.keyMod = ki.ModTime()
	}
	r.loadedAt = time.Now()
	return r.cert, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ci, cerr := os.Stat(r.certFile)
	ki, kerr := os.Stat(r.keyFile)
	if cerr == nil && kerr == nil && r.cert != nil &&
		ci.ModTime().Equal(r.certMod) && ki.ModTime().Equal(r.keyMod) {
		return r.cert, nil
	}
	cert, err := r.load()
	if err != nil {
		if r.cert != nil {
			// Keep serving the previous (still valid) pair on reload errors.
			return r.cert, nil
		}
		return nil, fmt.Errorf("load tls pair: %w", err)
	}
	return cert, nil
}

func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}
