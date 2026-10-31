package authvar

import (
	"testing"
	"time"

	"github.com/tpm2-trust/uefi/efivar"
	"github.com/tpm2-trust/uefi/internal/testkeys"
	"github.com/tpm2-trust/uefi/sigdb"
)

// An update of db signed by a KEK key: parsed, verified with that key's
// certificate, refused with another, refused for another variable,
// attributes or data.
func TestSignVerify(t *testing.T) {
	kekKey, kek := testkeys.RSA(t, "Key Exchange Key")
	_, other := testkeys.RSA(t, "Other")
	_, dbCert := testkeys.RSA(t, "Database Key")
	data, _ := sigdb.Database{sigdb.X509(sigdb.MicrosoftOwner, dbCert)}.Bytes()
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	upd, err := Sign(DB, Attributes, data, kekKey, kek, at)
	if err != nil {
		t.Fatal(err)
	}
	u, err := Parse(upd)
	if err != nil {
		t.Fatal(err)
	}
	if string(u.Data) != string(data) || u.Time != efivar.Time(at) {
		t.Fatal("data or time")
	}
	if err := u.Verify(DB, Attributes, kek); err != nil {
		t.Fatal(err)
	}
	if err := u.Verify(DB, Attributes, other); err == nil {
		t.Fatal("verified with another certificate")
	}
	if err := u.Verify(KEK, Attributes, kek); err == nil {
		t.Fatal("verified for another variable")
	}
	if err := u.Verify(DB, Attributes|efivar.AppendWrite, kek); err == nil {
		t.Fatal("verified with other attributes")
	}
	u.Data = append(u.Data[:len(u.Data)-1], u.Data[len(u.Data)-1]^1)
	if err := u.Verify(DB, Attributes, kek); err == nil {
		t.Fatal("verified with other data")
	}
}

func FuzzParse(f *testing.F) {
	key, cert := testkeys.RSA(f, "k")
	upd, _ := Sign(PK, Attributes, []byte{1, 2, 3}, key, cert, time.Now())
	f.Add(upd)
	f.Fuzz(func(t *testing.T, b []byte) {
		if u, err := Parse(b); err == nil {
			u.Verify(PK, Attributes, cert)
		}
	})
}
