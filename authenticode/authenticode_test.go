package authenticode

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/tpm2-trust/go-uefi-slim/internal/testkeys"
)

// minimalPE is a PE32+ with one section of data and trail after it.
func minimalPE(data, trail []byte) []byte {
	const peOff, opt = 0x80, 0x80 + 4 + 20
	img := make([]byte, 0x200)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], peOff)
	copy(img[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[peOff+4:], 0x8664) // Machine
	binary.LittleEndian.PutUint16(img[peOff+6:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(img[peOff+20:], 240)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(img[peOff+22:], 0x22)  // Characteristics
	binary.LittleEndian.PutUint16(img[opt:], 0x20b)      // PE32+
	binary.LittleEndian.PutUint32(img[opt+32:], 0x1000)  // SectionAlignment
	binary.LittleEndian.PutUint32(img[opt+36:], 0x200)   // FileAlignment
	binary.LittleEndian.PutUint32(img[opt+56:], 0x2000)  // SizeOfImage
	binary.LittleEndian.PutUint32(img[opt+60:], 0x200)   // SizeOfHeaders
	binary.LittleEndian.PutUint16(img[opt+68:], 10)      // EFI application
	binary.LittleEndian.PutUint32(img[opt+108:], 16)     // NumberOfRvaAndSizes
	sec := opt + 240
	copy(img[sec:], ".text")
	size := (len(data) + 0x1ff) &^ 0x1ff
	binary.LittleEndian.PutUint32(img[sec+8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(img[sec+12:], 0x1000)
	binary.LittleEndian.PutUint32(img[sec+16:], uint32(size))
	binary.LittleEndian.PutUint32(img[sec+20:], 0x200)
	binary.LittleEndian.PutUint32(img[sec+36:], 0x60000020)
	img = append(img, data...)
	img = append(img, make([]byte, size-len(data))...)
	return append(img, trail...)
}

// The hash leaves out the checksum and the certificate table's entry, and
// covers the sections and the trail.
func TestHash(t *testing.T) {
	img := minimalPE([]byte("code"), []byte("trail"))
	h, err := Hash(img)
	if err != nil {
		t.Fatal(err)
	}
	const opt = 0x80 + 4 + 20
	same := bytes.Clone(img)
	binary.LittleEndian.PutUint32(same[opt+64:], 0x12345678)      // the checksum
	binary.LittleEndian.PutUint64(same[opt+112+4*8:], 0xffffffff) // the certificate entry
	if h2, _ := Hash(same); !bytes.Equal(h, h2) {
		t.Fatal("the checksum or the certificate entry changed the hash")
	}
	for _, at := range []int{0x40, 0x200, len(img) - 1} {
		other := bytes.Clone(img)
		other[at] ^= 1
		if h2, _ := Hash(other); bytes.Equal(h, h2) {
			t.Errorf("byte 0x%x is not covered", at)
		}
	}
}

// Signed, verified with the signer's certificate, not with another; a
// change after signing fails; signing again replaces the signature.
func TestSignVerify(t *testing.T) {
	key, cert := testkeys.RSA(t, "Database Key")
	_, other := testkeys.RSA(t, "Other")
	img := minimalPE([]byte("code"), []byte("odd trail"))
	signed, err := Sign(img, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed)%8 != 0 {
		t.Fatalf("%d bytes, not 8-aligned", len(signed))
	}
	if err := Verify(signed, cert); err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, other); err == nil {
		t.Fatal("verified with another certificate")
	}
	if err := Verify(img, cert); err == nil {
		t.Fatal("an unsigned image verified")
	}
	changed := bytes.Clone(signed)
	changed[0x200] ^= 1
	if err := Verify(changed, cert); err == nil {
		t.Fatal("a changed image verified")
	}
	again, err := Sign(signed, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if sigs, err := Signatures(again); err != nil || len(sigs) != 1 || !sigs[0].Signer().Equal(cert) {
		t.Fatalf("signed again: %v %v", sigs, err)
	}
	if err := Verify(again, cert); err != nil {
		t.Fatal(err)
	}
}

// A real boot loader, where the machine has one: signed and verified.
func TestSystemdBoot(t *testing.T) {
	img, err := os.ReadFile("/usr/lib/systemd/boot/efi/systemd-bootx64.efi")
	if err != nil {
		t.Skip("no systemd-boot here")
	}
	key, cert := testkeys.RSA(t, "Database Key")
	signed, err := Sign(img, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, cert); err != nil {
		t.Fatal(err)
	}
}

func FuzzSignatures(f *testing.F) {
	key, cert := testkeys.RSA(f, "k")
	signed, _ := Sign(minimalPE([]byte("x"), nil), key, cert)
	f.Add(signed)
	f.Fuzz(func(t *testing.T, img []byte) {
		Signatures(img)
		Hash(img)
	})
}
