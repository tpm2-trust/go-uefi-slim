package sigdb

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"testing"
	"time"

	"github.com/tpm2-trust/uefi/efivar"
	"github.com/tpm2-trust/uefi/internal/testkeys"
)

// The GUIDs as edk2's ImageAuthentication.h initialises them, so that the
// text form above cannot drift from the binary one.
func TestTypeGUIDs(t *testing.T) {
	edk2 := func(d1 uint32, d2, d3 uint16, d4 ...byte) efivar.GUID {
		var g efivar.GUID
		binary.LittleEndian.PutUint32(g[0:], d1)
		binary.LittleEndian.PutUint16(g[4:], d2)
		binary.LittleEndian.PutUint16(g[6:], d3)
		copy(g[8:], d4)
		return g
	}
	for got, want := range map[efivar.GUID]efivar.GUID{
		CertSHA256:        edk2(0xc1c41626, 0x504c, 0x4092, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28),
		CertRSA2048:       edk2(0x3c5766e8, 0x269c, 0x4e34, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6),
		CertRSA2048SHA256: edk2(0xe2b36190, 0x879b, 0x4a3d, 0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84),
		CertSHA1:          edk2(0x826ca512, 0xcf10, 0x4ac9, 0xb1, 0x87, 0xbe, 0x1, 0x49, 0x66, 0x31, 0xbd),
		CertSM3:           edk2(0x57347f87, 0x7a9b, 0x403a, 0xb9, 0x3c, 0xdc, 0x4a, 0xfb, 0x7a, 0xe, 0xbc),
		CertRSA2048SHA1:   edk2(0x67f8444f, 0x8743, 0x48f1, 0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80),
		CertX509:          edk2(0xa5c059a1, 0x94e4, 0x4aa7, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72),
		CertX509SM3:       edk2(0x60d807e5, 0x10b4, 0x49a9, 0x93, 0x31, 0xe4, 0x4, 0x37, 0x88, 0x8d, 0x37),
		CertSHA224:        edk2(0xb6e5233, 0xa65c, 0x44c9, 0x94, 0x7, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd),
		CertSHA384:        edk2(0xff3e5307, 0x9fd0, 0x48c9, 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x1),
		CertSHA512:        edk2(0x93e0fae, 0xa6c4, 0x4f50, 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a),
		CertX509SHA256:    edk2(0x3bd2a492, 0x96c0, 0x4079, 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed),
		CertX509SHA384:    edk2(0x7076876e, 0x80c2, 0x4ee6, 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b),
		CertX509SHA512:    edk2(0x446dbf63, 0x2502, 0x4cda, 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d),
		// The specification's EFI_CERT_EXTERNAL_MANAGEMENT_GUID; edk2 does not define it.
		CertExternalManagement: edk2(0x452e8ced, 0xdfff, 0x4b8c, 0xae, 0x01, 0x51, 0x18, 0x86, 0x2e, 0x68, 0x2c),
	} {
		if got != want {
			t.Errorf("%s: %s, edk2 %s", TypeName(got), got, want)
		}
	}
	if len(types) != 15 {
		t.Errorf("%d types", len(types))
	}
}

// Every type of the specification, built at its size, written, read back
// the same; one byte off is refused by New, by Bytes and by Parse.
func TestEveryType(t *testing.T) {
	_, cert := testkeys.RSA(t, "x")
	var db Database
	for typ, st := range types {
		size := st.size
		if size == 0 {
			size = len(cert.Raw)
		}
		l, err := New(typ, owner, bytes.Repeat([]byte{1}, size), bytes.Repeat([]byte{2}, size))
		if err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		db = append(db, l)
		if st.size == 0 {
			continue
		}
		if _, err := New(typ, owner, make([]byte, size+1)); err == nil {
			t.Errorf("%s: an entry of %d bytes built", st.name, size+1)
		}
		short := List{Type: typ, Signatures: []Signature{{owner, make([]byte, size-1)}}}
		if _, err := (Database{short}).Bytes(); err == nil {
			t.Errorf("%s: an entry of %d bytes written", st.name, size-1)
		}
		if _, err := Parse(rawList(typ, nil, make([]byte, size-1))); err == nil {
			t.Errorf("%s: an entry of %d bytes read", st.name, size-1)
		}
	}
	b, err := db.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if b2, _ := back.Bytes(); !bytes.Equal(b, b2) || len(back) != len(types) {
		t.Fatal("not the same after a round trip")
	}
}

// rawList is one EFI_SIGNATURE_LIST as bytes, built without the checks.
func rawList(typ efivar.GUID, header []byte, entries ...[]byte) []byte {
	sigSize := 16 + len(entries[0])
	b := append([]byte{}, typ[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(listHeaderSize+len(header)+sigSize*len(entries)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(header)))
	b = binary.LittleEndian.AppendUint32(b, uint32(sigSize))
	b = append(b, header...)
	for _, e := range entries {
		b = append(b, owner[:]...)
		b = append(b, e...)
	}
	return b
}

// A header on a type of the specification is refused; a type it does not
// define is kept as it is, header and all.
func TestHeadersAndOtherTypes(t *testing.T) {
	if _, err := Parse(rawList(CertSHA256, []byte{1}, make([]byte, 32))); err == nil {
		t.Error("a SHA256 list with a header read")
	}
	other := efivar.MustParseGUID("11111111-2222-3333-4444-555555555555")
	b := rawList(other, []byte{9, 9}, []byte{1, 2, 3})
	db, err := Parse(b)
	if err != nil || len(db) != 1 || !bytes.Equal(db[0].Header, []byte{9, 9}) || TypeName(other) != other.String() {
		t.Fatalf("another type: %v %v", db, err)
	}
	if out, err := db.Bytes(); err != nil || !bytes.Equal(out, b) {
		t.Fatalf("another type written: %v", err)
	}
	if size, known := DataSize(other); known || size != 0 {
		t.Error("DataSize of another type")
	}
}

// X509Digest hashes the To-Be-Signed part and appends the revocation time,
// which X509Revocation reads back; the zero time is "always".
func TestX509Digest(t *testing.T) {
	_, cert := testkeys.RSA(t, "revoked")
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	l, err := X509Digest(CertX509SHA384, owner, cert, at)
	if err != nil {
		t.Fatal(err)
	}
	want := sha512.Sum384(cert.RawTBSCertificate)
	digest, revoked, ok := l.X509Revocation(l.Signatures[0])
	if !ok || !bytes.Equal(digest, want[:]) || !revoked.Equal(at) {
		t.Fatalf("%x %v %v", digest, revoked, ok)
	}
	l, _ = X509Digest(CertX509SHA256, owner, cert, time.Time{})
	if _, revoked, ok := l.X509Revocation(l.Signatures[0]); !ok || !revoked.IsZero() {
		t.Fatal("always revoked")
	}
	for _, typ := range []efivar.GUID{CertX509SM3, CertSHA256, CertX509} {
		if _, err := X509Digest(typ, owner, cert, at); err == nil {
			t.Errorf("X509Digest of %s", TypeName(typ))
		}
	}
	if _, _, ok := SHA256(owner, [32]byte{}).X509Revocation(Signature{Data: make([]byte, 48)}); ok {
		t.Error("X509Revocation of a SHA256 list")
	}
}

// RSA2048 takes a 2048-bit key with exponent 65537 alone, as its modulus;
// ExternalManagement is one zero byte.
func TestRSA2048AndExternalManagement(t *testing.T) {
	key, _ := testkeys.RSA(t, "x")
	pub := key.Public().(*rsa.PublicKey)
	l, err := RSA2048(owner, pub)
	if err != nil || !bytes.Equal(l.Signatures[0].Data, pub.N.Bytes()) {
		t.Fatalf("%v", err)
	}
	if _, err := RSA2048(owner, &rsa.PublicKey{N: pub.N, E: 3}); err == nil {
		t.Error("exponent 3 taken")
	}
	if b, err := (Database{ExternalManagement(owner)}).Bytes(); err != nil || len(b) != listHeaderSize+16+1 || b[len(b)-1] != 0 {
		t.Fatalf("external management: %x %v", b, err)
	}
}
