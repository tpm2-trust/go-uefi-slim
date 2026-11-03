// Package uki reads unified kernel images the way systemd-stub and the firmware
// measure them: the PE sections, what the stub extends into PCR 11 for each,
// the PCR signatures in .pcrsig (systemd-measure sign), and the file an image
// load event of PCR 4 names. It knows nothing of a TPM: whoever checks a
// signature or turns a value into a policy brings that.
package uki

import (
	"bytes"
	"crypto"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// PCRKernelBoot is the PCR systemd-stub measures the image into.
const PCRKernelBoot = 11

// ErrNoSection is a section the image does not have.
var ErrNoSection = errors.New("no such section")

// ErrNotUKI is an image with none of the sections systemd-stub measures.
var ErrNotUKI = errors.New("none of the sections systemd-stub measures")

// MeasuredSections are the sections systemd-stub measures into PCR 11, in its
// order, which is not the file's. .pcrsig is not among them: it carries the
// signature over these very measurements.
func MeasuredSections() []string {
	return []string{".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat", ".pcrpkey"}
}

// Image is a PE image opened for reading.
type Image struct {
	f *pe.File
	c io.Closer
}

// Open opens the image at path.
func Open(path string) (*Image, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("not a PE image: %w", err)
	}
	return &Image{f: f, c: f}, nil
}

// New reads an image from r, which it does not close.
func New(r io.ReaderAt) (*Image, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("not a PE image: %w", err)
	}
	return &Image{f: f}, nil
}

// Close closes what Open opened.
func (i *Image) Close() error {
	if i.c != nil {
		return i.c.Close()
	}
	return nil
}

// Section is the content of the first section called name and its size, without
// the padding up to the file alignment: VirtualSize, unless that is zero or
// more than the file holds. A section may be empty.
func (i *Image) Section(name string) (io.Reader, int64, error) {
	s := i.f.Section(name)
	if s == nil {
		return nil, 0, fmt.Errorf("%s: %w", name, ErrNoSection)
	}
	size := int64(s.VirtualSize)
	if size == 0 || size > int64(s.Size) {
		size = int64(s.Size)
	}
	return io.LimitReader(s.Open(), size), size, nil
}

// SectionData is Section's content, read whole.
func (i *Image) SectionData(name string) ([]byte, error) {
	r, size, err := i.Section(name)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if n, err := io.Copy(&b, r); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	} else if n != size {
		return nil, fmt.Errorf("%s: %d bytes of %d: %w", name, n, size, io.ErrUnexpectedEOF)
	}
	return b.Bytes(), nil
}

// MeasurementKind says what of a section a Measurement is.
type MeasurementKind string

const (
	MeasuredName    MeasurementKind = "name"    // the NUL-terminated ASCII name
	MeasuredContent MeasurementKind = "content" // the content, without padding
)

// Measurement is one digest systemd-stub extends into PCR 11.
type Measurement struct {
	Section string
	Kind    MeasurementKind
	Digest  []byte
}

// Measurements are the digests systemd-stub extends for the image in hash h, in
// order: for each section present and not empty, its name, then its content.
// The firmware's event log shows the name in UTF-16; the digest is of ASCII.
func (i *Image) Measurements(h crypto.Hash) ([]Measurement, error) {
	if !h.Available() {
		return nil, errors.New("this hash function is not linked in")
	}
	var out []Measurement
	for _, name := range MeasuredSections() {
		r, size, err := i.Section(name)
		if errors.Is(err, ErrNoSection) || size == 0 {
			continue
		}
		content := h.New()
		if n, err := io.Copy(content, r); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		} else if n != size {
			return nil, fmt.Errorf("%s: %d bytes of %d: %w", name, n, size, io.ErrUnexpectedEOF)
		}
		out = append(out,
			Measurement{Section: name, Kind: MeasuredName, Digest: Digest(h, append([]byte(name), 0))},
			Measurement{Section: name, Kind: MeasuredContent, Digest: content.Sum(nil)})
	}
	if len(out) == 0 {
		return nil, ErrNotUKI
	}
	return out, nil
}

// PCR11 is the value PCR 11 has from a zero start after the image's
// measurements and then the boot phases (the words systemd-pcrphase extends,
// enter-initrd first).
func (i *Image) PCR11(h crypto.Hash, phases []string) ([]byte, error) {
	ms, err := i.Measurements(h)
	if err != nil {
		return nil, err
	}
	pcr := make([]byte, h.Size())
	for _, m := range ms {
		pcr = Extend(h, pcr, m.Digest)
	}
	for _, p := range phases {
		pcr = Extend(h, pcr, Digest(h, []byte(p)))
	}
	return pcr, nil
}

// Digest is data's digest in hash h.
func Digest(h crypto.Hash, data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

// Extend is a PCR's value after an extend by digest.
func Extend(h crypto.Hash, pcr, digest []byte) []byte {
	d := h.New()
	d.Write(pcr)
	d.Write(digest)
	return d.Sum(nil)
}

// ImageLoadPath is the file path in a UEFI_IMAGE_LOAD_EVENT's device path (the
// data of EV_EFI_BOOT_SERVICES_APPLICATION, TCG PC Client Platform Firmware
// Profile): location, length and link address of the image, the device path's
// length and the path, whose media file path nodes (type 4, subtype 4) hold the
// file, in UTF-16. "" when it names none. That event's digest is the image's
// Authenticode hash (authenticode.HashWith).
func ImageLoadPath(data []byte) string {
	const header = 32
	if len(data) < header {
		return ""
	}
	length := binary.LittleEndian.Uint64(data[24:])
	if length > uint64(len(data)-header) {
		return ""
	}
	dp := data[header : header+int(length)]
	var path strings.Builder
	for len(dp) >= 4 {
		nodeLen := int(binary.LittleEndian.Uint16(dp[2:]))
		if nodeLen < 4 || nodeLen > len(dp) {
			return ""
		}
		if dp[0] == 4 && dp[1] == 4 {
			units := make([]uint16, 0, (nodeLen-4)/2)
			for b := dp[4:nodeLen]; len(b) >= 2 && (b[0] != 0 || b[1] != 0); b = b[2:] {
				units = append(units, binary.LittleEndian.Uint16(b))
			}
			path.WriteString(string(utf16.Decode(units)))
		}
		dp = dp[nodeLen:]
	}
	return path.String()
}
