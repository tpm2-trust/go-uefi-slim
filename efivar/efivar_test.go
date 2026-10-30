package efivar

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var testGUID = MustParseGUID("2b0f2e5c-6a51-4d63-9f3a-9b1f6c1c7a10")

const plain = NonVolatile | BootServiceAccess | RuntimeAccess

func TestGUID(t *testing.T) {
	// Data1, Data2, Data3 little endian, Data4 as it is.
	want := GUID{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
	if GlobalVariable != want {
		t.Fatalf("binary form: %x", GlobalVariable[:])
	}
	if s := GlobalVariable.String(); s != "8be4df61-93ca-11d2-aa0d-00e098032b8c" {
		t.Fatalf("string: %s", s)
	}
	if g, err := ParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C"); err != nil || g != GlobalVariable {
		t.Fatalf("upper case: %v %v", g, err)
	}
	for _, bad := range []string{"", "8be4df61-93ca-11d2-aa0d-00e098032b8", "8be4df6193ca11d2aa0d00e098032b8c0000", "8be4df61-93ca-11d2-aa0d-00e098032b8g"} {
		if _, err := ParseGUID(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// A variable written, replaced by a shorter one, appended to, read with
// its attributes, listed, removed; none there is os.ErrNotExist.
func TestStore(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, _, err := s.Read("Test", testGUID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("before: %v", err)
	}
	for _, v := range []string{"a longer value", "short"} {
		if err := s.Write("Test", testGUID, plain, []byte(v)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(s.Dir, "Test-"+testGUID.String()))
		if err != nil || string(raw) != "\x07\x00\x00\x00"+v {
			t.Fatalf("file: %q %v", raw, err)
		}
		attrs, data, err := s.Read("Test", testGUID)
		if err != nil || attrs != plain || string(data) != v {
			t.Fatalf("read: %x %q %v", attrs, data, err)
		}
	}
	if err := s.Write("Test", testGUID, plain|AppendWrite, []byte("+more")); err != nil {
		t.Fatal(err)
	}
	// On a plain directory the attributes are appended too; efivarfs
	// strips them. What matters here: nothing was truncated.
	if raw, _ := os.ReadFile(filepath.Join(s.Dir, "Test-"+testGUID.String())); !bytes.HasPrefix(raw, []byte("\x07\x00\x00\x00short")) {
		t.Fatalf("append truncated: %q", raw)
	}
	vars, err := s.List()
	if err != nil || len(vars) != 1 || vars[0] != (Variable{"Test", testGUID}) {
		t.Fatalf("list: %v %v", vars, err)
	}
	if err := s.Write("Test", testGUID, plain, nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty write: %v", err)
	}
	if err := s.Remove("Test", testGUID); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("Test", testGUID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed twice: %v", err)
	}
	for _, bad := range []string{"", "a/b", "a b", "\x00"} {
		if _, err := s.Path(bad, testGUID); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	if err := (Store{Dir: filepath.Join(s.Dir, "none")}).Write("Test", testGUID, plain, []byte("x")); err == nil {
		t.Fatal("written without a directory")
	}
}

// The firmware's one-byte variables, and other attributes.
func TestReadBool(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if on, err := s.ReadBool("SecureBoot", GlobalVariable); on || err != nil {
		t.Fatalf("missing: %v %v", on, err)
	}
	os.WriteFile(filepath.Join(s.Dir, "SecureBoot-"+GlobalVariable.String()), []byte{0x06, 0, 0, 0, 1}, 0o644)
	if on, err := s.ReadBool("SecureBoot", GlobalVariable); !on || err != nil {
		t.Fatalf("on: %v %v", on, err)
	}
	os.WriteFile(filepath.Join(s.Dir, "SetupMode-"+GlobalVariable.String()), []byte{0x06, 0, 0, 0, 1, 2}, 0o644)
	if _, err := s.ReadBool("SetupMode", GlobalVariable); err == nil {
		t.Fatal("two bytes taken as a bool")
	}
}

// Checking a missing variable's mark creates nothing.
func TestImmutableMissing(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.Immutable("Test", testGUID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if entries, _ := os.ReadDir(s.Dir); len(entries) != 0 {
		t.Fatal("a check created a file")
	}
}

// The mark lifted for a write and put back, also when the write fails,
// and lifted for a removal. Needs CAP_LINUX_IMMUTABLE and a file system
// with the bit (tmpfs since Linux 6.0); skipped otherwise.
func TestImmutable(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	path, _ := s.Path("Test", testGUID)
	if err := os.WriteFile(path, []byte{7, 0, 0, 0, 1}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := setImmutable(path, true); err != nil {
		t.Skipf("no immutable bit here: %v", err)
	}
	if on, _ := s.Immutable("Test", testGUID); !on {
		t.Skip("the file system keeps no immutable bit")
	}
	t.Cleanup(func() { setImmutable(path, false) })

	if err := s.Write("Test", testGUID, plain, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.Immutable("Test", testGUID); !on {
		t.Fatal("not put back after a write")
	}
	// A write that fails: the directory read-only for it, as root is not
	// stopped by modes - a file in its place that cannot be opened for
	// writing is a directory.
	dir := Store{Dir: t.TempDir()}
	dpath, _ := dir.Path("Test", testGUID)
	os.Mkdir(dpath, 0o755)
	if _, err := setImmutable(dpath, true); err == nil {
		if err := dir.Write("Test", testGUID, plain, []byte("x")); err == nil {
			t.Fatal("written over a directory")
		}
		if on, _ := dir.Immutable("Test", testGUID); !on {
			t.Fatal("not put back after a failed write")
		}
		setImmutable(dpath, false)
	}
	if err := s.Remove("Test", testGUID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("not removed")
	}
}

func FuzzParseGUID(f *testing.F) {
	f.Add("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		g, err := ParseGUID(s)
		if err != nil {
			return
		}
		if back, err := ParseGUID(g.String()); err != nil || back != g {
			t.Fatalf("%q: %v round trip %v %v", s, g, back, err)
		}
	})
}
