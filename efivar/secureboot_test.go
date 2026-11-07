package efivar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each state from the two variables, and one that cannot be read as such, never as off.
func TestSecureBootState(t *testing.T) {
	for _, c := range []struct {
		name                  string
		secureBoot, setupMode []byte
		enabled, setup, known bool
		risk                  string
	}{
		{"on", []byte{1}, []byte{0}, true, false, true, ""},
		{"off", []byte{0}, []byte{0}, false, false, true, "is off"},
		{"setup mode", []byte{0}, []byte{1}, false, true, true, "Setup Mode"},
		{"no variables", nil, nil, false, false, false, "could not be read"},
		{"a bad size", []byte{1, 1}, []byte{0}, false, false, false, "not one"},
	} {
		dir := t.TempDir()
		for name, data := range map[string][]byte{"SecureBoot": c.secureBoot, "SetupMode": c.setupMode} {
			if data == nil {
				continue
			}
			os.WriteFile(filepath.Join(dir, name+"-"+GlobalVariable.String()), append([]byte{6, 0, 0, 0}, data...), 0o600)
		}
		st := Store{Dir: dir}.SecureBootState()
		if st.Known != c.known || st.Known && (st.Enabled != c.enabled || st.SetupMode != c.setup) {
			t.Errorf("%s: %+v", c.name, st)
		}
		if r := st.Risk(); (c.risk == "") != (r == "") || !strings.Contains(r, c.risk) {
			t.Errorf("%s: risk %q, want %q", c.name, r, c.risk)
		}
	}
}
