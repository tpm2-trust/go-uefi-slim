// Package efivar reads, writes and removes EFI variables through efivarfs.
//
// A variable is a file named NAME-GUID in efivarfs; its contents are the
// variable's attributes, four bytes little endian, followed by its data.
// efivarfs takes a write whole or not at all and replaces the variable with
// it, so a write never leaves half a variable. efivarfs marks most
// variables immutable against an accidental rm: a Store lifts the mark for
// its own write or removal and puts it back afterwards, whether that
// succeeded or not.
package efivar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Attributes are a variable's EFI_VARIABLE_* bits.
type Attributes uint32

const (
	NonVolatile                       Attributes = 0x01
	BootServiceAccess                 Attributes = 0x02
	RuntimeAccess                     Attributes = 0x04
	HardwareErrorRecord               Attributes = 0x08
	AuthenticatedWriteAccess          Attributes = 0x10
	TimeBasedAuthenticatedWriteAccess Attributes = 0x20
	AppendWrite                       Attributes = 0x40
)

// DefaultDir is where efivarfs is mounted.
const DefaultDir = "/sys/firmware/efi/efivars"

// ErrEmpty is a write of no data: efivarfs takes it as a removal.
var ErrEmpty = errors.New("an EFI variable cannot be written empty (that removes it)")

// Store is efivarfs, or a directory that stands in for it (tests). The zero
// value is efivarfs at DefaultDir.
type Store struct {
	Dir string
}

func (s Store) dir() string {
	if s.Dir == "" {
		return DefaultDir
	}
	return s.Dir
}

// Path is the file of the variable name of vendor guid. A name is
// printable ASCII without '/', at most 512 characters.
func (s Store) Path(name string, guid GUID) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.dir(), name+"-"+guid.String()), nil
}

func checkName(name string) error {
	if name == "" || len(name) > 512 {
		return fmt.Errorf("%q: not an EFI variable name", name)
	}
	for _, c := range name {
		if c < 0x21 || c > 0x7e || c == '/' {
			return fmt.Errorf("%q: not an EFI variable name (printable ASCII, no '/')", name)
		}
	}
	return nil
}

// Read is the variable's attributes and data; an error that
// errors.Is(err, os.ErrNotExist) knows when there is none.
func (s Store) Read(name string, guid GUID) (Attributes, []byte, error) {
	path, err := s.Path(name, guid)
	if err != nil {
		return 0, nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("%s: shorter than its attributes", path)
	}
	return Attributes(binary.LittleEndian.Uint32(b)), b[4:], nil
}

// Write replaces the variable with data, in one write; with AppendWrite in
// attrs it appends to it (the firmware's rule for signature lists). An
// authenticated variable's data carries its EFI_VARIABLE_AUTHENTICATION_2
// in front.
func (s Store) Write(name string, guid GUID, attrs Attributes, data []byte) (err error) {
	path, err := s.Path(name, guid)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return ErrEmpty
	}
	if _, err := os.Stat(s.dir()); err != nil {
		return fmt.Errorf("no efivarfs at %s: %w", s.dir(), err)
	}
	restore, err := liftImmutable(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, restore()) }()

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if attrs&AppendWrite != 0 {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(data)), uint32(attrs))
	b = append(b, data...)
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("writing %s (%d bytes): %w", path, len(b), werr)
	}
	return cerr
}

// Remove removes the variable; one that is not there is an error that
// errors.Is(err, os.ErrNotExist) knows.
func (s Store) Remove(name string, guid GUID) (err error) {
	path, err := s.Path(name, guid)
	if err != nil {
		return err
	}
	restore, err := liftImmutable(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		// Still there, and so is its mark.
		return errors.Join(err, restore())
	}
	return nil
}

// Variable names one variable.
type Variable struct {
	Name string
	GUID GUID
}

// List is every variable in the store.
func (s Store) List() ([]Variable, error) {
	entries, err := os.ReadDir(s.dir())
	if err != nil {
		return nil, err
	}
	var vars []Variable
	for _, e := range entries {
		n := e.Name()
		if len(n) < 38 || n[len(n)-37] != '-' {
			continue
		}
		g, err := ParseGUID(n[len(n)-36:])
		if err != nil {
			continue
		}
		vars = append(vars, Variable{Name: n[:len(n)-37], GUID: g})
	}
	return vars, nil
}

// ReadBool is a one-byte variable as a bool (SecureBoot, SetupMode): false
// when there is none.
func (s Store) ReadBool(name string, guid GUID) (bool, error) {
	_, b, err := s.Read(name, guid)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(b) != 1 {
		return false, fmt.Errorf("%s: %d bytes, not one", name, len(b))
	}
	return b[0] == 1, nil
}

// String names the variable as efivarfs does.
func (v Variable) String() string { return v.Name + "-" + v.GUID.String() }

// IsNotExist reports whether err says a variable is not there.
func IsNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
