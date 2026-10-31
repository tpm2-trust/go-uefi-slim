package sigdb

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
)

// Signature types of the UEFI specification (2.10, 32.4.1; edk2's
// ImageAuthentication.h). Every one has a header of size 0.
var (
	// CertX509 is an X.509 certificate, DER: entries of any size, so one
	// per list.
	CertX509 = efivar.MustParseGUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")

	// Digests of an image (or, in dbx, of anything the firmware hashes).
	CertSHA1   = efivar.MustParseGUID("826ca512-cf10-4ac9-b187-be01496631bd")
	CertSHA224 = efivar.MustParseGUID("0b6e5233-a65c-44c9-9407-d9ab83bfc8bd")
	CertSHA256 = efivar.MustParseGUID("c1c41626-504c-4092-aca9-41f936934328")
	CertSHA384 = efivar.MustParseGUID("ff3e5307-9fd0-48c9-85f1-8ad56c701e01")
	CertSHA512 = efivar.MustParseGUID("093e0fae-a6c4-4f50-9f1b-d41e2b89c19a")
	CertSM3    = efivar.MustParseGUID("57347f87-7a9b-403a-b93c-dc4afb7a0ebc")

	// CertRSA2048 is an RSA-2048 key: its modulus, big endian (the
	// exponent is 65537).
	CertRSA2048 = efivar.MustParseGUID("3c5766e8-269c-4e34-aa14-ed776e85b3b6")
	// CertRSA2048SHA1 and CertRSA2048SHA256 are RSA-2048 signatures of a
	// digest.
	CertRSA2048SHA1   = efivar.MustParseGUID("67f8444f-8743-48f1-a328-1eaab8736080")
	CertRSA2048SHA256 = efivar.MustParseGUID("e2b36190-879b-4a3d-ad8d-f2e7bba32784")

	// The digest of a certificate's To-Be-Signed part and the EFI_TIME it
	// is revoked from (all zero: always): dbx entries.
	CertX509SHA256 = efivar.MustParseGUID("3bd2a492-96c0-4079-b420-fcf98ef103ed")
	CertX509SHA384 = efivar.MustParseGUID("7076876e-80c2-4ee6-aad2-28b349a6865b")
	CertX509SHA512 = efivar.MustParseGUID("446dbf63-2502-4cda-bcfa-2465d2b0fe9d")
	CertX509SM3    = efivar.MustParseGUID("60d807e5-10b4-49a9-9331-e40437888d37")

	// CertExternalManagement says the database is managed outside the
	// firmware: one byte, zero.
	CertExternalManagement = efivar.MustParseGUID("452e8ced-dfff-4b8c-ae01-5118862e682c")
)

type sigType struct {
	name string
	size int // of an entry's data; 0: any (X.509)
	hash crypto.Hash
}

var types = map[efivar.GUID]sigType{
	CertX509:               {"X509", 0, 0},
	CertSHA1:               {"SHA1", 20, crypto.SHA1},
	CertSHA224:             {"SHA224", 28, crypto.SHA224},
	CertSHA256:             {"SHA256", 32, crypto.SHA256},
	CertSHA384:             {"SHA384", 48, crypto.SHA384},
	CertSHA512:             {"SHA512", 64, crypto.SHA512},
	CertSM3:                {"SM3", 32, 0},
	CertRSA2048:            {"RSA2048", 256, 0},
	CertRSA2048SHA1:        {"RSA2048_SHA1", 256, 0},
	CertRSA2048SHA256:      {"RSA2048_SHA256", 256, 0},
	CertX509SHA256:         {"X509_SHA256", 32 + efivar.TimeSize, crypto.SHA256},
	CertX509SHA384:         {"X509_SHA384", 48 + efivar.TimeSize, crypto.SHA384},
	CertX509SHA512:         {"X509_SHA512", 64 + efivar.TimeSize, crypto.SHA512},
	CertX509SM3:            {"X509_SM3", 32 + efivar.TimeSize, 0},
	CertExternalManagement: {"EXTERNAL_MANAGEMENT", 1, 0},
}

// TypeName is the type's name in the specification without EFI_CERT_ and
// _GUID ("X509_SHA256"), or the GUID of a type it does not define.
func TypeName(t efivar.GUID) string {
	if st, ok := types[t]; ok {
		return st.name
	}
	return t.String()
}

// DataSize is the size of an entry's data of type t: 0 where it varies
// (X.509); known is false for a type the specification does not define.
func DataSize(t efivar.GUID) (size int, known bool) {
	st, ok := types[t]
	return st.size, ok
}

// check holds a list to its type's rules: no header, entries of the
// type's size. A type the specification does not define is taken as it is.
func (l List) check() error {
	st, ok := types[l.Type]
	if !ok {
		return nil
	}
	if len(l.Header) != 0 {
		return fmt.Errorf("a %s list with a header", st.name)
	}
	for _, s := range l.Signatures {
		if st.size != 0 && len(s.Data) != st.size {
			return fmt.Errorf("a %s entry of %d bytes, not %d", st.name, len(s.Data), st.size)
		}
		if st.size == 0 && len(s.Data) == 0 {
			return fmt.Errorf("an empty %s entry", st.name)
		}
	}
	return nil
}

// New is a list of type t with one entry per data, each held to the
// type's size.
func New(t efivar.GUID, owner efivar.GUID, data ...[]byte) (List, error) {
	l := List{Type: t}
	for _, d := range data {
		l.Signatures = append(l.Signatures, Signature{Owner: owner, Data: bytes.Clone(d)})
	}
	return l, l.check()
}

// X509 is a list of one certificate, as sbctl and efitools enrol them.
func X509(owner efivar.GUID, cert *x509.Certificate) List {
	return List{Type: CertX509, Signatures: []Signature{{Owner: owner, Data: bytes.Clone(cert.Raw)}}}
}

// SHA256 is a list of image digests.
func SHA256(owner efivar.GUID, digests ...[sha256.Size]byte) List {
	l := List{Type: CertSHA256}
	for _, d := range digests {
		l.Signatures = append(l.Signatures, Signature{Owner: owner, Data: bytes.Clone(d[:])})
	}
	return l
}

// X509Digest is a list that revokes cert by the digest of its To-Be-Signed
// part (t: CertX509SHA256, CertX509SHA384 or CertX509SHA512): from
// revoked on, or always for the zero time. X509_SM3 has no hash in Go's
// standard library: build it with New.
func X509Digest(t efivar.GUID, owner efivar.GUID, cert *x509.Certificate, revoked time.Time) (List, error) {
	st, ok := types[t]
	if !ok || st.hash == 0 || st.size != st.hash.Size()+efivar.TimeSize {
		return List{}, fmt.Errorf("%s is not an X.509 digest type this package hashes", TypeName(t))
	}
	h := st.hash.New()
	h.Write(cert.RawTBSCertificate)
	ts := efivar.Time(revoked)
	return New(t, owner, append(h.Sum(nil), ts[:]...))
}

// RSA2048 is a list of one RSA-2048 key with the exponent 65537.
func RSA2048(owner efivar.GUID, pub *rsa.PublicKey) (List, error) {
	if pub.N.BitLen() != 2048 || pub.E != 65537 {
		return List{}, fmt.Errorf("an RSA key of %d bits, exponent %d: RSA2048 takes 2048 bits, 65537", pub.N.BitLen(), pub.E)
	}
	return New(CertRSA2048, owner, pub.N.FillBytes(make([]byte, 256)))
}

// ExternalManagement is the list that marks a database as managed outside
// the firmware.
func ExternalManagement(owner efivar.GUID) List {
	return List{Type: CertExternalManagement, Signatures: []Signature{{Owner: owner, Data: []byte{0}}}}
}

// X509Revocation reads an entry of an X.509 digest type: the digest of a
// certificate's To-Be-Signed part, and the time it is revoked from (zero:
// always). ok is false for an entry of another type.
func (l List) X509Revocation(s Signature) (digest []byte, revoked time.Time, ok bool) {
	switch l.Type {
	case CertX509SHA256, CertX509SHA384, CertX509SHA512, CertX509SM3:
	default:
		return nil, time.Time{}, false
	}
	n := len(s.Data) - efivar.TimeSize
	if n <= 0 {
		return nil, time.Time{}, false
	}
	return bytes.Clone(s.Data[:n]), efivar.ParseTime([efivar.TimeSize]byte(s.Data[n:])), true
}
