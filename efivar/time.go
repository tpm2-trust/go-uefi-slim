package efivar

import (
	"encoding/binary"
	"time"
)

// TimeSize is the size of an EFI_TIME.
const TimeSize = 16

// Time is t as an EFI_TIME in UTC: Year (uint16, little endian), Month,
// Day, Hour, Minute, Second, a pad byte, then Nanosecond, TimeZone,
// Daylight and a pad byte, all zero - the form the firmware takes in a
// signed update's timestamp and a revocation time. The zero time.Time is
// the all-zero EFI_TIME.
func Time(t time.Time) [TimeSize]byte {
	var b [TimeSize]byte
	if t.IsZero() {
		return b
	}
	t = t.UTC()
	binary.LittleEndian.PutUint16(b[0:], uint16(t.Year()))
	b[2], b[3], b[4], b[5], b[6] = byte(t.Month()), byte(t.Day()), byte(t.Hour()), byte(t.Minute()), byte(t.Second())
	return b
}

// ParseTime reads an EFI_TIME; the all-zero one is the zero time.Time. The
// time zone is taken as UTC, as the firmware's variables use it.
func ParseTime(b [TimeSize]byte) time.Time {
	if b == ([TimeSize]byte{}) {
		return time.Time{}
	}
	return time.Date(int(binary.LittleEndian.Uint16(b[0:])), time.Month(b[2]), int(b[3]),
		int(b[4]), int(b[5]), int(b[6]), int(binary.LittleEndian.Uint32(b[8:])), time.UTC)
}
