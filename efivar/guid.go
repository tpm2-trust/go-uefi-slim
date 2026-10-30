package efivar

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// GUID is an EFI_GUID in its binary form: Data1, Data2 and Data3 little
// endian, Data4 as it is - the way the firmware and every structure that
// holds one store it.
type GUID [16]byte

// Well-known vendor GUIDs.
var (
	// GlobalVariable owns the variables of the UEFI specification
	// (SecureBoot, SetupMode, PK, KEK, BootOrder, ...).
	GlobalVariable = MustParseGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	// ImageSecurityDatabase owns db, dbx, dbt and dbr.
	ImageSecurityDatabase = MustParseGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	// Shim owns shim's variables (MokListRT, SbatLevelRT, ...).
	Shim = MustParseGUID("605dab50-e046-4300-abb6-3dd810dd8b23")
)

// ParseGUID reads the textual form, "8be4df61-93ca-11d2-aa0d-00e098032b8c",
// in either case.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return g, fmt.Errorf("%q: not a GUID", s)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return g, fmt.Errorf("%q: not a GUID", s)
	}
	binary.LittleEndian.PutUint32(g[0:4], binary.BigEndian.Uint32(b[0:4]))
	binary.LittleEndian.PutUint16(g[4:6], binary.BigEndian.Uint16(b[4:6]))
	binary.LittleEndian.PutUint16(g[6:8], binary.BigEndian.Uint16(b[6:8]))
	copy(g[8:], b[8:])
	return g, nil
}

// MustParseGUID is ParseGUID for constants; it panics on a malformed one.
func MustParseGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

// String is the textual form, lower case, as efivarfs names files.
func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:4]), binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]), g[8:10], g[10:16])
}
