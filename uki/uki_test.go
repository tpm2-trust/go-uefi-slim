package uki

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

type section struct {
	name string
	data []byte
	// virtual is VirtualSize; -1 is len(data). Raw data is padded to 0x200.
	virtual int
}

// peWith is a PE32+ of these sections, each padded with NULs to the file alignment.
func peWith(secs ...section) []byte {
	const peOff, opt = 0x80, 0x80 + 4 + 20
	head := (opt + 240 + 40*len(secs) + 0x1ff) &^ 0x1ff
	img := make([]byte, head)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], peOff)
	copy(img[peOff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[peOff+4:], 0x8664)
	binary.LittleEndian.PutUint16(img[peOff+6:], uint16(len(secs)))
	binary.LittleEndian.PutUint16(img[peOff+20:], 240)
	binary.LittleEndian.PutUint16(img[peOff+22:], 0x22)
	binary.LittleEndian.PutUint16(img[opt:], 0x20b)
	binary.LittleEndian.PutUint32(img[opt+32:], 0x1000)
	binary.LittleEndian.PutUint32(img[opt+36:], 0x200)
	binary.LittleEndian.PutUint32(img[opt+60:], uint32(head))
	binary.LittleEndian.PutUint16(img[opt+68:], 10)
	binary.LittleEndian.PutUint32(img[opt+108:], 16)
	for n, s := range secs {
		at := opt + 240 + 40*n
		copy(img[at:], s.name)
		virtual := s.virtual
		if virtual < 0 {
			virtual = len(s.data)
		}
		raw := (len(s.data) + 0x1ff) &^ 0x1ff
		binary.LittleEndian.PutUint32(img[at+8:], uint32(virtual))
		binary.LittleEndian.PutUint32(img[at+12:], uint32(0x1000*(n+1)))
		binary.LittleEndian.PutUint32(img[at+16:], uint32(raw))
		binary.LittleEndian.PutUint32(img[at+20:], uint32(len(img)))
		binary.LittleEndian.PutUint32(img[at+36:], 0x40000040)
		img = append(img, s.data...)
		img = append(img, make([]byte, raw-len(s.data))...)
	}
	return img
}

func image(t *testing.T, secs ...section) *Image {
	t.Helper()
	i, err := New(bytes.NewReader(peWith(secs...)))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// The content is measured without padding; VirtualSize 0 or beyond the raw size
// falls back on the raw size.
func TestSectionUnpadded(t *testing.T) {
	i := image(t, section{".linux", []byte("kernel"), -1}, section{".osrel", []byte("id"), 0}, section{".cmdline", []byte("x"), 0x10000})
	if b, err := i.SectionData(".linux"); err != nil || string(b) != "kernel" {
		t.Fatalf("unpadded: %q %v", b, err)
	}
	if b, err := i.SectionData(".osrel"); err != nil || len(b) != 0x200 {
		t.Fatalf("VirtualSize 0: %d bytes, %v", len(b), err)
	}
	if b, err := i.SectionData(".cmdline"); err != nil || len(b) != 0x200 {
		t.Fatalf("VirtualSize too large: %d bytes, %v", len(b), err)
	}
	if _, err := i.SectionData(".none"); !errors.Is(err, ErrNoSection) {
		t.Fatalf("a section not there: %v", err)
	}
}

// The stub's order, not the file's; name then content; .pcrsig and others not measured.
func TestMeasurements(t *testing.T) {
	i := image(t, section{".osrel", []byte("ID=x"), -1}, section{".pcrsig", []byte("{}"), -1},
		section{".other", []byte("y"), -1}, section{".linux", []byte("kernel"), -1})
	ms, err := i.Measurements(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	want := []Measurement{
		{".linux", MeasuredName, Digest(crypto.SHA256, []byte(".linux\x00"))},
		{".linux", MeasuredContent, Digest(crypto.SHA256, []byte("kernel"))},
		{".osrel", MeasuredName, Digest(crypto.SHA256, []byte(".osrel\x00"))},
		{".osrel", MeasuredContent, Digest(crypto.SHA256, []byte("ID=x"))},
	}
	if len(ms) != len(want) {
		t.Fatalf("%d measurements: %+v", len(ms), ms)
	}
	for n := range want {
		if ms[n].Section != want[n].Section || ms[n].Kind != want[n].Kind || !bytes.Equal(ms[n].Digest, want[n].Digest) {
			t.Fatalf("measurement %d: %+v, want %+v", n, ms[n], want[n])
		}
	}
	if _, err := image(t, section{".text", []byte("x"), -1}).Measurements(crypto.SHA256); !errors.Is(err, ErrNotUKI) {
		t.Fatalf("no measured section: %v", err)
	}
	if _, err := i.Measurements(crypto.Hash(0)); err == nil {
		t.Fatal("no hash function")
	}
}

// A section the file does not hold whole is an error, not a shorter digest.
func TestMeasurementsTruncated(t *testing.T) {
	img := peWith(section{".linux", bytes.Repeat([]byte("k"), 0x400), -1})
	i, err := New(bytes.NewReader(img[:len(img)-0x100]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Measurements(crypto.SHA256); err == nil {
		t.Fatal("a truncated section was measured")
	}
	if _, err := i.SectionData(".linux"); err == nil {
		t.Fatal("a truncated section was read")
	}
}

// PCR 11 as systemd itself computes it.
func TestPCR11AsSystemdMeasure(t *testing.T) {
	tool := "/usr/lib/systemd/systemd-measure"
	if _, err := os.Stat(tool); err != nil {
		t.Skip("no systemd-measure")
	}
	dir := t.TempDir()
	parts := map[string][]byte{".linux": []byte("kernel image"), ".osrel": []byte("ID=test\n"), ".cmdline": []byte("root=x ro"), ".initrd": bytes.Repeat([]byte("i"), 0x345)}
	args := []string{"calculate", "--bank=sha256", "--bank=sha1", "--phase=enter-initrd", "--json=short"}
	var secs []section
	for name, data := range parts {
		f := filepath.Join(dir, name[1:])
		if err := os.WriteFile(f, data, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--"+name[1:]+"="+f)
		secs = append(secs, section{name, data, -1})
	}
	out, err := exec.Command(tool, args...).Output()
	if err != nil {
		t.Skipf("systemd-measure: %v", err)
	}
	var got map[string][]struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	i := image(t, secs...)
	for bank, h := range map[string]crypto.Hash{"sha256": crypto.SHA256, "sha1": crypto.SHA1} {
		v, err := i.PCR11(h, []string{"enter-initrd"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got[bank]) != 1 || got[bank][0].Hash != hex.EncodeToString(v) {
			t.Fatalf("%s: %x, systemd-measure says %s", bank, v, out)
		}
	}
}

func TestPCRSignatures(t *testing.T) {
	pol := []byte{1, 2, 3}
	sig := []byte("the signature")
	js, _ := json.Marshal(PCRSignatures{"sha256": {
		{PCRs: []int{7}, Pol: hex.EncodeToString(pol), Sig: base64.StdEncoding.EncodeToString([]byte("other pcrs"))},
		{PCRs: []int{11}, Pol: "not hex", Sig: base64.StdEncoding.EncodeToString([]byte("bad pol"))},
		{PCRs: []int{11}, Pol: hex.EncodeToString(pol), Sig: "not base64!"},
		{PCRs: []int{11}, Pol: hex.EncodeToString(pol), Sig: base64.StdEncoding.EncodeToString([]byte("refused"))},
		{PCRs: []int{11}, Pkfp: "aa", Pol: hex.EncodeToString(pol), Sig: base64.StdEncoding.EncodeToString(sig)},
	}})
	i := image(t, section{".linux", []byte("k"), -1}, section{".pcrsig", append(bytes.Clone(js), 0, 0), -1})
	p, err := i.PCRSignatures()
	if err != nil {
		t.Fatal(err)
	}
	if p["sha256"][4].Pkfp != "aa" {
		t.Fatalf("%+v", p)
	}
	accept := func(s []byte) error {
		if !bytes.Equal(s, sig) {
			return errors.New("no")
		}
		return nil
	}
	if got := p.Find("sha256", []int{11}, pol, accept); !bytes.Equal(got, sig) {
		t.Fatalf("Find: %q", got)
	}
	if got := p.Find("sha1", []int{11}, pol, accept); got != nil {
		t.Fatalf("another bank: %q", got)
	}
	if got := p.Find("sha256", []int{11}, []byte{9}, accept); got != nil {
		t.Fatalf("another policy: %q", got)
	}
	if got := p.Find("sha256", []int{11}, pol, func([]byte) error { return errors.New("no") }); got != nil {
		t.Fatalf("nothing verifies: %q", got)
	}
	if _, err := ParsePCRSignatures([]byte("not json\x00")); err == nil {
		t.Fatal("not JSON")
	}
	if _, err := ParsePCRSignatures(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := image(t, section{".linux", []byte("k"), -1}).PCRSignatures(); !errors.Is(err, ErrNoSection) {
		t.Fatalf("no .pcrsig: %v", err)
	}
}

// loadEvent is a UEFI_IMAGE_LOAD_EVENT with these device path nodes.
func loadEvent(nodes ...[]byte) []byte {
	dp := bytes.Join(nodes, nil)
	data := make([]byte, 32, 32+len(dp))
	binary.LittleEndian.PutUint64(data[24:], uint64(len(dp)))
	return append(data, dp...)
}

func fileNode(path string) []byte {
	units := append(utf16.Encode([]rune(path)), 0)
	n := make([]byte, 4, 4+2*len(units))
	n[0], n[1] = 4, 4
	binary.LittleEndian.PutUint16(n[2:], uint16(4+2*len(units)))
	for _, u := range units {
		n = binary.LittleEndian.AppendUint16(n, u)
	}
	return n
}

func TestImageLoadPath(t *testing.T) {
	end := []byte{0x7f, 0xff, 4, 0}
	other := []byte{1, 4, 6, 0, 9, 9}
	if got := ImageLoadPath(loadEvent(other, fileNode(`\EFI\BOOT\BOOTX64.EFI`), end)); got != `\EFI\BOOT\BOOTX64.EFI` {
		t.Fatalf("%q", got)
	}
	if got := ImageLoadPath(loadEvent(other, end)); got != "" {
		t.Fatalf("no file: %q", got)
	}
	if got := ImageLoadPath(make([]byte, 31)); got != "" {
		t.Fatalf("short: %q", got)
	}
	long := loadEvent(end)
	binary.LittleEndian.PutUint64(long[24:], 1<<40)
	if got := ImageLoadPath(long); got != "" {
		t.Fatalf("length beyond the data: %q", got)
	}
	if got := ImageLoadPath(loadEvent([]byte{4, 4, 200, 0, 1, 1})); got != "" {
		t.Fatalf("node beyond the path: %q", got)
	}
	if got := ImageLoadPath(loadEvent([]byte{4, 4, 2, 0})); got != "" {
		t.Fatalf("node shorter than its header: %q", got)
	}
}

func FuzzParsePCRSignatures(f *testing.F) {
	f.Add([]byte(`{"sha256":[{"pcrs":[11],"pkfp":"aa","pol":"0102","sig":"AQI="}]}` + "\x00\x00"))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"sha256":[{"pcrs":"x"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePCRSignatures(b)
		if err != nil {
			return
		}
		for bank, es := range p {
			for _, e := range es {
				pol, _ := hex.DecodeString(e.Pol)
				p.Find(bank, e.PCRs, pol, func([]byte) error { return nil })
			}
		}
	})
}

func FuzzImage(f *testing.F) {
	f.Add(peWith(section{".linux", []byte("kernel"), -1}, section{".pcrsig", []byte(`{}`), -1}))
	f.Add(peWith(section{".linux", []byte("kernel"), 0x10000}))
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, b []byte) {
		i, err := New(bytes.NewReader(b))
		if err != nil {
			return
		}
		defer i.Close()
		i.PCR11(crypto.SHA256, []string{"enter-initrd"})
		i.PCRSignatures()
	})
}

func FuzzImageLoadPath(f *testing.F) {
	f.Add(loadEvent(fileNode(`\EFI\Linux\arch.efi`), []byte{0x7f, 0xff, 4, 0}))
	f.Add(make([]byte, 32))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { ImageLoadPath(b) })
}
