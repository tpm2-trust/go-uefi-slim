package mscerts

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// What was downloaded from Microsoft, and only that.
func TestPinned(t *testing.T) {
	want := map[string]bool{}
	for _, h := range []string{
		"a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503", // KEK/MicCorKEKCA2011_2011-06-24.der
		"3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d", // KEK/microsoft-corporation-kek-2k-ca-2023.der
		"48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507", // db/MicCorUEFCA2011_2011-06-27.der
		"e5be3e64c6e66a281457ecdece0d6d0787577aad2a3a0144262c10c14ba8d8f1", // db/microsoft-option-rom-uefi-ca-2023.der
		"f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901", // db/microsoft-uefi-ca-2023.der
		"e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961", // db/MicWinProPCA2011_2011-10-19.der
		"076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330", // db/windows-uefi-ca-2023.der
	} {
		want[h] = true
	}
	kek, err := KEK()
	if err != nil || len(kek) != 2 {
		t.Fatalf("KEK: %d %v", len(kek), err)
	}
	db, err := DB()
	if err != nil || len(db) != 5 {
		t.Fatalf("db: %d %v", len(db), err)
	}
	for _, c := range append(kek, db...) {
		h := sha256.Sum256(c.Raw)
		if !want[hex.EncodeToString(h[:])] {
			t.Errorf("%s: not pinned", c.Subject)
		}
	}
}
