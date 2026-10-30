// Package mscerts holds Microsoft's Secure Boot certificates, as sbctl
// enrols them with --microsoft: the KEK CAs (2011, 2023), and the db CAs
// for Windows, third parties (shim, option ROMs) and option ROMs (2011,
// 2023). They are public; each was downloaded from Microsoft (fwlink, the
// microsoft/secureboot_objects repository) and found identical to sbctl's
// copy (2026-10-30). The test pins their SHA-256.
package mscerts

import (
	"crypto/x509"
	"embed"
	"io/fs"
	"path"
	"sort"
)

//go:embed KEK/*.der db/*.der
var files embed.FS

// KEK are the certificates for KEK.
func KEK() ([]*x509.Certificate, error) { return load("KEK") }

// DB are the certificates for db. The option ROM CAs among them matter on
// machines whose graphics or network card's firmware they sign: without
// them such a machine may not show a picture.
func DB() ([]*x509.Certificate, error) { return load("db") }

func load(dir string) ([]*x509.Certificate, error) {
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []*x509.Certificate
	for _, e := range entries {
		b, err := files.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
