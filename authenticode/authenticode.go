// Package authenticode signs and verifies PE images (boot loaders, unified
// kernel images) the way UEFI Secure Boot checks them.
//
// The image's hash is the firmware's (edk2's DxeImageVerificationLib):
// the headers without the checksum and without the certificate table's
// data directory entry, then the sections in file order, then whatever
// follows them except the certificate table. The signature is a PKCS#7
// SignedData whose content, SpcIndirectDataContent, holds that hash; it is
// appended as a WIN_CERTIFICATE (8-byte aligned) and named by the
// certificate table's entry. What is built here is what sbsign and sbctl
// build.
package authenticode

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tpm2-trust/uefi/internal/pkcs7"
)

var (
	oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPEImageData  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
)

const (
	winCertRevision       = 0x0200
	winCertTypeSignedData = 0x0002
	securityDir           = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
)

// layout is where in the file the parts of the hash are.
type layout struct {
	checksum      int // offset of OptionalHeader.CheckSum
	certEntry     int // offset of the certificate table's entry; -1 when none
	sizeOfHeaders int
	sections      [][2]int // file offset, size, in file order
	certOffset    int      // the certificate table, from its entry
	certSize      int
}

func parse(img []byte) (*layout, error) {
	f, err := pe.NewFile(bytes.NewReader(img))
	if err != nil {
		return nil, fmt.Errorf("not a PE image: %w", err)
	}
	defer f.Close()
	if len(img) < 0x40 {
		return nil, errors.New("not a PE image")
	}
	peOff := int(binary.LittleEndian.Uint32(img[0x3c:]))
	opt := peOff + 4 + 20
	l := &layout{checksum: opt + 64, certEntry: -1}
	var dirs int
	var nDirs uint32
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		l.sizeOfHeaders, dirs, nDirs = int(h.SizeOfHeaders), opt+96, h.NumberOfRvaAndSizes
		if nDirs > securityDir {
			l.certOffset, l.certSize = int(h.DataDirectory[securityDir].VirtualAddress), int(h.DataDirectory[securityDir].Size)
		}
	case *pe.OptionalHeader64:
		l.sizeOfHeaders, dirs, nDirs = int(h.SizeOfHeaders), opt+112, h.NumberOfRvaAndSizes
		if nDirs > securityDir {
			l.certOffset, l.certSize = int(h.DataDirectory[securityDir].VirtualAddress), int(h.DataDirectory[securityDir].Size)
		}
	default:
		return nil, errors.New("a PE image without an optional header")
	}
	if nDirs > securityDir {
		l.certEntry = dirs + securityDir*8
	}
	if l.sizeOfHeaders > len(img) || l.checksum+4 > l.sizeOfHeaders || (l.certEntry >= 0 && l.certEntry+8 > l.sizeOfHeaders) {
		return nil, errors.New("the PE headers run past the image")
	}
	if l.certSize > 0 && (l.certOffset < l.sizeOfHeaders || l.certOffset+l.certSize != len(img)) {
		return nil, errors.New("the certificate table is not at the image's end")
	}
	for _, s := range f.Sections {
		if s.Size == 0 {
			continue
		}
		if int(s.Offset)+int(s.Size) > len(img) {
			return nil, fmt.Errorf("section %s runs past the image", s.Name)
		}
		l.sections = append(l.sections, [2]int{int(s.Offset), int(s.Size)})
	}
	slices.SortFunc(l.sections, func(a, b [2]int) int { return a[0] - b[0] })
	return l, nil
}

func (l *layout) hash(img []byte) []byte {
	h := sha256.New()
	h.Write(img[:l.checksum])
	if l.certEntry >= 0 {
		h.Write(img[l.checksum+4 : l.certEntry])
		h.Write(img[l.certEntry+8 : l.sizeOfHeaders])
	} else {
		h.Write(img[l.checksum+4 : l.sizeOfHeaders])
	}
	sum := l.sizeOfHeaders
	for _, s := range l.sections {
		h.Write(img[s[0] : s[0]+s[1]])
		sum += s[1]
	}
	if end := len(img) - l.certSize; end > sum {
		h.Write(img[sum:end])
	}
	return h.Sum(nil)
}

// Hash is the image's Authenticode SHA-256, as the firmware computes it.
func Hash(img []byte) ([]byte, error) {
	l, err := parse(img)
	if err != nil {
		return nil, err
	}
	return l.hash(img), nil
}

// indirectData is SpcIndirectDataContent for a PE image with its digest.
func indirectData(digest []byte) ([]byte, error) {
	// SpcPeImageData: no flags, the file as the obsolete link every signer
	// writes: [0] { [2] { [0] BMPString "<<<Obsolete>>>" } }.
	obsolete := []byte{}
	for _, r := range "<<<Obsolete>>>" {
		obsolete = append(obsolete, 0, byte(r))
	}
	link := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true,
		Bytes: mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: obsolete})}
	file := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(link)}
	peImage, err := asn1.Marshal(struct {
		Flags asn1.BitString
		File  asn1.RawValue
	}{File: file})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Data struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		MessageDigest struct {
			Algorithm pkcs7.AlgorithmIdentifier
			Digest    []byte
		}
	}{
		Data: struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}{oidSpcPEImageData, asn1.RawValue{FullBytes: peImage}},
		MessageDigest: struct {
			Algorithm pkcs7.AlgorithmIdentifier
			Digest    []byte
		}{pkcs7.SHA256, digest},
	})
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// contents are a DER value's contents octets, without tag and length: what
// Authenticode's message digest covers.
func contents(der []byte) ([]byte, error) {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return nil, err
	}
	return v.Bytes, nil
}

// Sign is the image signed by key with cert: any signature it had is
// replaced, the image padded to 8 bytes, the signature appended, the
// certificate table's entry and the checksum set.
func Sign(img []byte, key crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	l, err := parse(img)
	if err != nil {
		return nil, err
	}
	if l.certEntry < 0 {
		return nil, errors.New("the image has no certificate table entry")
	}
	out := bytes.Clone(img[:len(img)-l.certSize])
	binary.LittleEndian.PutUint64(out[l.certEntry:], 0)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	l, err = parse(out)
	if err != nil {
		return nil, err
	}
	content, err := indirectData(l.hash(out))
	if err != nil {
		return nil, err
	}
	digested, err := contents(content)
	if err != nil {
		return nil, err
	}
	sd, err := pkcs7.Sign(key, cert, pkcs7.Options{
		ContentType: oidSpcIndirectData,
		Content:     content,
		Digested:    digested,
		SigningTime: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	wrapped, err := pkcs7.Wrap(sd)
	if err != nil {
		return nil, err
	}
	size := 8 + len(wrapped)
	for size%8 != 0 {
		size++
	}
	certOff := len(out)
	out = binary.LittleEndian.AppendUint32(out, uint32(size))
	out = binary.LittleEndian.AppendUint16(out, winCertRevision)
	out = binary.LittleEndian.AppendUint16(out, winCertTypeSignedData)
	out = append(out, wrapped...)
	for len(out) < certOff+size {
		out = append(out, 0)
	}
	binary.LittleEndian.PutUint32(out[l.certEntry:], uint32(certOff))
	binary.LittleEndian.PutUint32(out[l.certEntry+4:], uint32(size))
	binary.LittleEndian.PutUint32(out[l.checksum:], checksum(out, l.checksum))
	return out, nil
}

// checksum is the PE checksum: the 16-bit one's-complement-style sum of
// the file, without the checksum field, plus the file's length.
func checksum(img []byte, at int) uint32 {
	var sum uint32
	for i := 0; i+1 < len(img); i += 2 {
		if i == at || i == at+2 {
			continue
		}
		sum += uint32(binary.LittleEndian.Uint16(img[i:]))
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if len(img)%2 == 1 {
		sum += uint32(img[len(img)-1])
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return (sum & 0xffff) + uint32(len(img))
}

// Signature is one signature of an image.
type Signature struct {
	signed *pkcs7.Signed
	digest []byte // the image hash it vouches for
}

// Signer is the signer's certificate, as the signature carries it.
func (s *Signature) Signer() *x509.Certificate { return s.signed.Signer() }

// Signatures are the image's Authenticode signatures.
func Signatures(img []byte) ([]*Signature, error) {
	l, err := parse(img)
	if err != nil {
		return nil, err
	}
	var out []*Signature
	t := img[len(img)-l.certSize:]
	for len(t) >= 8 {
		length := int(binary.LittleEndian.Uint32(t))
		if length < 8 || length > len(t) {
			return nil, errors.New("a WIN_CERTIFICATE runs past the certificate table")
		}
		if binary.LittleEndian.Uint16(t[4:]) == winCertRevision && binary.LittleEndian.Uint16(t[6:]) == winCertTypeSignedData {
			// The entry's length takes in its padding to 8 bytes: the
			// signature is the DER element at its start.
			var der asn1.RawValue
			if _, err := asn1.Unmarshal(t[8:length], &der); err != nil {
				return nil, err
			}
			s, err := pkcs7.Parse(der.FullBytes)
			if err != nil {
				return nil, err
			}
			if !s.ContentType.Equal(oidSpcIndirectData) {
				return nil, errors.New("a signature whose content is not SpcIndirectDataContent")
			}
			var idc struct {
				Data          asn1.RawValue
				MessageDigest struct {
					Algorithm pkcs7.AlgorithmIdentifier
					Digest    []byte
				}
			}
			if _, err := asn1.Unmarshal(s.Content, &idc); err != nil {
				return nil, err
			}
			out = append(out, &Signature{signed: s, digest: idc.MessageDigest.Digest})
		}
		length = (length + 7) &^ 7
		if length > len(t) {
			break
		}
		t = t[length:]
	}
	return out, nil
}

// Verify checks that img carries a signature over its present contents by
// trust's key, or by a certificate trust signed.
func Verify(img []byte, trust *x509.Certificate) error {
	sigs, err := Signatures(img)
	if err != nil {
		return err
	}
	if len(sigs) == 0 {
		return errors.New("the image is not signed")
	}
	h, err := Hash(img)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range sigs {
		if !bytes.Equal(s.digest, h) {
			errs = append(errs, errors.New("a signature over other contents"))
			continue
		}
		digested, err := contents(s.signed.Content)
		if err != nil {
			return err
		}
		if err := s.signed.Verify(digested, trust); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}
	return errors.Join(errs...)
}
