// Command vmcheck tries this module on a machine's firmware (a test VM in
// Setup Mode): it makes Secure Boot keys the way sbctl lays them out,
// signs boot files, enrols db, KEK and PK, and reports the state. Not for
// a machine anyone uses: enrolling PK leaves Setup Mode for good.
//
//	vmcheck state
//	vmcheck enrol KEYDIR FILE...   keys into KEYDIR (sbctl's: /var/lib/sbctl),
//	                               FILEs signed in place, keys enrolled with
//	                               Microsoft's
//	vmcheck verify KEYDIR FILE...  FILEs checked against KEYDIR's db key
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/tpm2-trust/go-uefi-slim/authenticode"
	"github.com/tpm2-trust/go-uefi-slim/authvar"
	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/go-uefi-slim/mscerts"
	"github.com/tpm2-trust/go-uefi-slim/sigdb"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: vmcheck state | enrol KEYDIR FILE... | verify KEYDIR FILE..."))
	}
	var err error
	switch os.Args[1] {
	case "state":
		err = state()
	case "enrol":
		err = enrol(os.Args[2], os.Args[3:])
	case "verify":
		err = verify(os.Args[2], os.Args[3:])
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	fail(err)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "vmcheck:", err)
		os.Exit(1)
	}
}

func state() error {
	s := efivar.Store{}
	sb, err := s.ReadBool("SecureBoot", efivar.GlobalVariable)
	if err != nil {
		return err
	}
	sm, err := s.ReadBool("SetupMode", efivar.GlobalVariable)
	if err != nil {
		return err
	}
	fmt.Printf("SecureBoot=%v SetupMode=%v\n", sb, sm)
	for _, v := range []authvar.Variable{authvar.PK, authvar.KEK, authvar.DB, authvar.DBX} {
		_, data, err := s.Read(v.Name, v.GUID)
		if efivar.IsNotExist(err) {
			fmt.Printf("%s: none\n", v.Name)
			continue
		}
		if err != nil {
			return err
		}
		db, err := sigdb.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", v.Name, err)
		}
		certs, err := db.Certificates()
		if err != nil {
			return err
		}
		n := 0
		for _, l := range db {
			n += len(l.Signatures)
		}
		fmt.Printf("%s: %d entries\n", v.Name, n)
		for _, c := range certs {
			fmt.Printf("  %s (owner %s)\n", c.Cert.Subject.CommonName, c.Owner)
		}
	}
	return nil
}

// key is one of sbctl's: HIER/HIER.key (PKCS#8, "PRIVATE KEY") and
// HIER/HIER.pem.
type key struct {
	signer crypto.Signer
	cert   *x509.Certificate
}

func makeKey(dir, hier, cn string) (*key, error) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: cn, Country: []string{"WW"}},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	d := filepath.Join(dir, "keys", hier)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(d, hier+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(d, hier+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return &key{k, cert}, nil
}

func readKey(dir, hier string) (*key, error) {
	kb, err := os.ReadFile(filepath.Join(dir, "keys", hier, hier+".key"))
	if err != nil {
		return nil, err
	}
	cb, err := os.ReadFile(filepath.Join(dir, "keys", hier, hier+".pem"))
	if err != nil {
		return nil, err
	}
	kp, _ := pem.Decode(kb)
	cp, _ := pem.Decode(cb)
	if kp == nil || cp == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kp.Bytes)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, err
	}
	return &key{k.(crypto.Signer), c}, nil
}

func enrol(dir string, files []string) error {
	s := efivar.Store{}
	if sm, err := s.ReadBool("SetupMode", efivar.GlobalVariable); err != nil || !sm {
		return fmt.Errorf("not in Setup Mode (%v)", err)
	}
	// sbctl's GUID file: the owner of the machine's own certificates, a
	// random (version 4) GUID per machine.
	var owner efivar.GUID
	if _, err := rand.Read(owner[:]); err != nil {
		return err
	}
	owner[7] = owner[7]&0x0f | 0x40 // Data3's high nibble: version 4
	owner[8] = owner[8]&0x3f | 0x80 // the variant
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "GUID"), []byte(owner.String()), 0o644); err != nil {
		return err
	}
	pk, err := makeKey(dir, "PK", "Platform Key")
	if err != nil {
		return err
	}
	kek, err := makeKey(dir, "KEK", "Key Exchange Key")
	if err != nil {
		return err
	}
	db, err := makeKey(dir, "db", "Database Key")
	if err != nil {
		return err
	}
	for _, f := range files {
		img, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		signed, err := authenticode.Sign(img, db.signer, db.cert)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := authenticode.Verify(signed, db.cert); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := os.WriteFile(f, signed, 0o644); err != nil {
			return err
		}
		fmt.Println("signed", f)
	}
	msDB, err := mscerts.DB()
	if err != nil {
		return err
	}
	msKEK, err := mscerts.KEK()
	if err != nil {
		return err
	}
	dbList := sigdb.Database{sigdb.X509(owner, db.cert)}
	for _, c := range msDB {
		dbList = append(dbList, sigdb.X509(sigdb.MicrosoftOwner, c))
	}
	kekList := sigdb.Database{sigdb.X509(owner, kek.cert)}
	for _, c := range msKEK {
		kekList = append(kekList, sigdb.X509(sigdb.MicrosoftOwner, c))
	}
	pkList := sigdb.Database{sigdb.X509(owner, pk.cert)}
	now := time.Now()
	// db by KEK, KEK by PK, PK by itself; PK last: it ends Setup Mode.
	for _, e := range []struct {
		v      authvar.Variable
		list   sigdb.Database
		signer *key
	}{{authvar.DB, dbList, kek}, {authvar.KEK, kekList, pk}, {authvar.PK, pkList, pk}} {
		data, err := e.list.Bytes()
		if err != nil {
			return err
		}
		upd, err := authvar.Sign(e.v, authvar.Attributes, data, e.signer.signer, e.signer.cert, now)
		if err != nil {
			return err
		}
		if err := s.Write(e.v.Name, e.v.GUID, authvar.Attributes, upd); err != nil {
			return fmt.Errorf("enrolling %s: %w", e.v.Name, err)
		}
		fmt.Printf("enrolled %s (%d bytes)\n", e.v.Name, len(data))
	}
	return state()
}

func verify(dir string, files []string) error {
	db, err := readKey(dir, "db")
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range files {
		img, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := authenticode.Verify(img, db.cert); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
			continue
		}
		fmt.Println("verified", f)
	}
	return errors.Join(errs...)
}
