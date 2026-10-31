package efivar

import (
	"testing"
	"time"
)

// EFI_TIME: UTC, year little endian, then month to second; nothing else.
// The zero time is all zero both ways.
func TestTime(t *testing.T) {
	at := time.Date(2026, 10, 30, 12, 34, 56, 789, time.FixedZone("x", 3600))
	got := Time(at)
	if want := [TimeSize]byte{0xea, 0x07, 10, 30, 11, 34, 56}; got != want {
		t.Fatalf("%x", got)
	}
	if back := ParseTime(got); !back.Equal(at.Truncate(time.Second)) {
		t.Fatalf("read back: %v", back)
	}
	if Time(time.Time{}) != [TimeSize]byte{} || !ParseTime([TimeSize]byte{}).IsZero() {
		t.Fatal("zero")
	}
}
