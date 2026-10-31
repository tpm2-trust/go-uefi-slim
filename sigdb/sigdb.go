// Package sigdb reads and builds UEFI signature databases: the contents
// of PK, KEK, db, dbx and shim's MokListRT, a sequence of
// EFI_SIGNATURE_LISTs.
//
//	EFI_SIGNATURE_LIST: SignatureType (GUID), SignatureListSize,
//	SignatureHeaderSize, SignatureSize (uint32 each, little endian), the
//	header, then the entries: SignatureOwner (GUID) and the signature's
//	data, SignatureSize bytes together.
//
// Every type of the UEFI specification is read and built, each held to
// its size (types.go); a list of another type is kept as it is.
package sigdb

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tpm2-trust/uefi/efivar"
)

// MicrosoftOwner is the owner GUID Microsoft's certificates are enrolled
// under.
var MicrosoftOwner = efivar.MustParseGUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")

// Signature is one entry of a list.
type Signature struct {
	Owner efivar.GUID
	Data  []byte
}

// List is an EFI_SIGNATURE_LIST: entries of one type and one size.
type List struct {
	Type       efivar.GUID
	Header     []byte
	Signatures []Signature
}

// Database is a variable's contents: lists one after the other.
type Database []List

const listHeaderSize = 16 + 4 + 4 + 4

// Parse reads a database; an empty one is no lists.
func Parse(b []byte) (Database, error) {
	var db Database
	for len(b) > 0 {
		if len(b) < listHeaderSize {
			return nil, errors.New("a signature list shorter than its header")
		}
		var l List
		copy(l.Type[:], b[:16])
		listSize := binary.LittleEndian.Uint32(b[16:])
		headerSize := binary.LittleEndian.Uint32(b[20:])
		sigSize := binary.LittleEndian.Uint32(b[24:])
		if uint64(listSize) > uint64(len(b)) || listSize < listHeaderSize {
			return nil, fmt.Errorf("a signature list of %d bytes in %d", listSize, len(b))
		}
		body := b[listHeaderSize:listSize]
		if uint64(headerSize) > uint64(len(body)) {
			return nil, errors.New("a signature list's header beyond the list")
		}
		l.Header = bytes.Clone(body[:headerSize])
		body = body[headerSize:]
		if sigSize < 16 || len(body)%int(sigSize) != 0 {
			return nil, fmt.Errorf("signature size %d does not divide %d bytes", sigSize, len(body))
		}
		for len(body) > 0 {
			var s Signature
			copy(s.Owner[:], body[:16])
			s.Data = bytes.Clone(body[16:sigSize])
			l.Signatures = append(l.Signatures, s)
			body = body[sigSize:]
		}
		if err := l.check(); err != nil {
			return nil, err
		}
		db = append(db, l)
		b = b[listSize:]
	}
	return db, nil
}

// Bytes is the database as the variable holds it. Every entry of a list
// must have the size of its first.
func (db Database) Bytes() ([]byte, error) {
	var out []byte
	for _, l := range db {
		if len(l.Signatures) == 0 {
			continue
		}
		if err := l.check(); err != nil {
			return nil, err
		}
		sigSize := 16 + len(l.Signatures[0].Data)
		size := listHeaderSize + len(l.Header) + sigSize*len(l.Signatures)
		out = append(out, l.Type[:]...)
		out = binary.LittleEndian.AppendUint32(out, uint32(size))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(l.Header)))
		out = binary.LittleEndian.AppendUint32(out, uint32(sigSize))
		out = append(out, l.Header...)
		for _, s := range l.Signatures {
			if 16+len(s.Data) != sigSize {
				return nil, errors.New("entries of different sizes in one signature list")
			}
			out = append(out, s.Owner[:]...)
			out = append(out, s.Data...)
		}
	}
	return out, nil
}

// Entry is a certificate of a database with its owner.
type Entry struct {
	Owner efivar.GUID
	Cert  *x509.Certificate
}

// Certificates are the X.509 entries of the database; one that does not
// parse is an error.
func (db Database) Certificates() ([]Entry, error) {
	var out []Entry
	for _, l := range db {
		if l.Type != CertX509 {
			continue
		}
		for _, s := range l.Signatures {
			c, err := x509.ParseCertificate(s.Data)
			if err != nil {
				return nil, fmt.Errorf("a certificate of owner %s: %w", s.Owner, err)
			}
			out = append(out, Entry{Owner: s.Owner, Cert: c})
		}
	}
	return out, nil
}

// Contains reports whether the database holds data of type t.
func (db Database) Contains(t efivar.GUID, data []byte) bool {
	for _, l := range db {
		if l.Type != t {
			continue
		}
		for _, s := range l.Signatures {
			if bytes.Equal(s.Data, data) {
				return true
			}
		}
	}
	return false
}
