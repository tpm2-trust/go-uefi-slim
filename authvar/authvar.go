// Package authvar builds and checks signed updates of time-based
// authenticated variables (PK, KEK, db, dbx): EFI_VARIABLE_AUTHENTICATION_2
// in front of the new data.
//
//	EFI_VARIABLE_AUTHENTICATION_2: TimeStamp (EFI_TIME, 16 bytes), then a
//	WIN_CERTIFICATE_UEFI_GUID: dwLength, wRevision 0x0200,
//	wCertificateType 0x0EF1, CertType EFI_CERT_TYPE_PKCS7_GUID, and a
//	PKCS#7 SignedData (no ContentInfo) over VariableName (UTF-16LE, no NUL),
//	VendorGuid, Attributes, TimeStamp and the data.
//
// In Setup Mode the firmware takes any signer; in User Mode PK signs PK and
// KEK, a KEK key signs db and dbx. What is built here is what sbctl and
// efitools' sign-efi-sig-list build.
package authvar

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/go-uefi-slim/internal/pkcs7"
)

// Attributes are those of an authenticated Secure Boot variable; with
// efivar.AppendWrite an update adds to it.
const Attributes = efivar.NonVolatile | efivar.BootServiceAccess | efivar.RuntimeAccess | efivar.TimeBasedAuthenticatedWriteAccess

// CertTypePKCS7 is EFI_CERT_TYPE_PKCS7_GUID.
var CertTypePKCS7 = efivar.MustParseGUID("4aafd29d-68df-49ee-8aa9-347d375665a7")

const (
	winCertRevision = 0x0200
	winCertTypeGUID = 0x0EF1
	winCertHdrSize  = 4 + 2 + 2 + 16
)

// Variable names a Secure Boot variable with its vendor.
type Variable struct {
	Name string
	GUID efivar.GUID
}

// The Secure Boot variables.
var (
	PK  = Variable{"PK", efivar.GlobalVariable}
	KEK = Variable{"KEK", efivar.GlobalVariable}
	DB  = Variable{"db", efivar.ImageSecurityDatabase}
	DBX = Variable{"dbx", efivar.ImageSecurityDatabase}
)

// signedBytes is what the signature covers.
func signedBytes(v Variable, attrs efivar.Attributes, ts [efivar.TimeSize]byte, data []byte) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(v.Name)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	b = append(b, v.GUID[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(attrs))
	b = append(b, ts[:]...)
	return append(b, data...)
}

// Sign is the update of v to data, signed by key with cert at time at: the
// EFI_VARIABLE_AUTHENTICATION_2 followed by data, ready for
// efivar.Store.Write with attrs (Attributes, or with efivar.AppendWrite).
// An update replaces the variable only with a timestamp later than the
// one it has.
func Sign(v Variable, attrs efivar.Attributes, data []byte, key crypto.Signer, cert *x509.Certificate, at time.Time) ([]byte, error) {
	ts := efivar.Time(at)
	sd, err := pkcs7.Sign(key, cert, pkcs7.Options{
		ContentType: pkcs7.OIDData,
		Digested:    signedBytes(v, attrs, ts, data),
		SigningTime: at,
	})
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, ts[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(winCertHdrSize+len(sd)))
	out = binary.LittleEndian.AppendUint16(out, winCertRevision)
	out = binary.LittleEndian.AppendUint16(out, winCertTypeGUID)
	out = append(out, CertTypePKCS7[:]...)
	out = append(out, sd...)
	return append(out, data...), nil
}

// Update is a parsed signed update.
type Update struct {
	Time      [efivar.TimeSize]byte
	Signature []byte // the PKCS#7 SignedData
	Data      []byte
}

// Parse splits a signed update into its timestamp, signature and data.
func Parse(b []byte) (*Update, error) {
	if len(b) < efivar.TimeSize+winCertHdrSize {
		return nil, errors.New("shorter than EFI_VARIABLE_AUTHENTICATION_2")
	}
	var u Update
	copy(u.Time[:], b)
	w := b[efivar.TimeSize:]
	length := binary.LittleEndian.Uint32(w)
	if binary.LittleEndian.Uint16(w[4:]) != winCertRevision || binary.LittleEndian.Uint16(w[6:]) != winCertTypeGUID {
		return nil, errors.New("not a WIN_CERTIFICATE_UEFI_GUID")
	}
	if efivar.GUID(w[8:24]) != CertTypePKCS7 {
		return nil, errors.New("not a PKCS#7 certificate type")
	}
	if length < winCertHdrSize || uint64(length) > uint64(len(w)) {
		return nil, fmt.Errorf("a WIN_CERTIFICATE of %d bytes in %d", length, len(w))
	}
	u.Signature = w[winCertHdrSize:length]
	u.Data = w[length:]
	return &u, nil
}

// Verify checks that the update of v with attrs is signed by trust (or by a
// certificate trust signed).
func (u *Update) Verify(v Variable, attrs efivar.Attributes, trust *x509.Certificate) error {
	s, err := pkcs7.Parse(u.Signature)
	if err != nil {
		return err
	}
	return s.Verify(signedBytes(v, attrs, u.Time, u.Data), trust)
}
