package sigdb

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/go-uefi-slim/internal/testkeys"
)

var owner = efivar.MustParseGUID("2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10")

// A certificate list and a digest list, built, read back, found.
func TestRoundTrip(t *testing.T) {
	_, cert := testkeys.RSA(t, "Database Key")
	d1, d2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	db := Database{X509(owner, cert), SHA256(MicrosoftOwner, d1, d2)}
	b, err := db.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// One list: 28 bytes of header, then owner and certificate.
	if got := len(b); got != 28+16+len(cert.Raw)+28+2*(16+32) {
		t.Fatalf("%d bytes", got)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if b2, _ := back.Bytes(); !bytes.Equal(b, b2) {
		t.Fatal("not the same after a round trip")
	}
	certs, err := back.Certificates()
	if err != nil || len(certs) != 1 || !certs[0].Cert.Equal(cert) || certs[0].Owner != owner {
		t.Fatalf("certificates: %v %v", certs, err)
	}
	if !back.Contains(CertSHA256, d2[:]) || back.Contains(CertSHA256, cert.Raw) {
		t.Fatal("Contains")
	}
	if db, err := Parse(nil); err != nil || len(db) != 0 {
		t.Fatalf("empty: %v %v", db, err)
	}
}

// Truncated or inconsistent lists are refused, never read past.
func TestParseRefuses(t *testing.T) {
	_, cert := testkeys.RSA(t, "x")
	b, _ := Database{X509(owner, cert)}.Bytes()
	for _, bad := range [][]byte{b[:10], b[:len(b)-1], append(bytes.Clone(b), 1)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%d bytes taken", len(bad))
		}
	}
}

func FuzzParse(f *testing.F) {
	_, cert := testkeys.RSA(f, "x")
	b, _ := Database{X509(owner, cert)}.Bytes()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		db, err := Parse(b)
		if err != nil {
			return
		}
		out, err := db.Bytes()
		if err == nil && len(out) > len(b) {
			t.Fatalf("%d bytes from %d", len(out), len(b))
		}
	})
}
