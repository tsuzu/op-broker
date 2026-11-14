package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "op.tsuzu.dev"},
		DNSNames:     []string{"op.tsuzu.dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Ensure mtime visibly changes between rotations.
	future := time.Now().Add(time.Duration(serial) * time.Second)
	_ = os.Chtimes(filepath.Join(dir, "tls.crt"), future, future)
	_ = os.Chtimes(filepath.Join(dir, "tls.key"), future, future)
}

func TestCertReloaderRotation(t *testing.T) {
	dir := t.TempDir()
	writeSelfSigned(t, dir, 1001)
	rl, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rl.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Int64() != 1001 {
		t.Fatalf("serial = %d, want 1001", leaf.SerialNumber)
	}
	// Rotate the files (what cert-manager does on renewal) and confirm the
	// new pair is picked up without a restart.
	writeSelfSigned(t, dir, 1002)
	cert, err = rl.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.Int64() != 1002 {
		t.Fatalf("after rotation serial = %d, want 1002", leaf.SerialNumber)
	}
}
