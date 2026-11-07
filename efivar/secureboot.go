package efivar

import (
	"fmt"
	"strings"
)

// SecureBootState is the firmware's word on Secure Boot: its SecureBoot and SetupMode
// variables. It says what the firmware says, not what was measured: a verifier
// establishes the state from PCR 7 and its events.
type SecureBootState struct {
	Enabled   bool
	SetupMode bool
	Known     bool   // both variables were read
	Why       string // why not, when not
}

// SecureBootState reads the state.
func (s Store) SecureBootState() SecureBootState {
	var st SecureBootState
	var problems []string
	var err error
	if st.Enabled, err = s.readFlag("SecureBoot"); err != nil {
		problems = append(problems, err.Error())
	}
	if st.SetupMode, err = s.readFlag("SetupMode"); err != nil {
		problems = append(problems, err.Error())
	}
	st.Known = len(problems) == 0
	st.Why = strings.Join(problems, "; ")
	return st
}

// readFlag reads a one-byte variable of the UEFI specification's namespace; one that
// is not there is an error, not false.
func (s Store) readFlag(name string) (bool, error) {
	_, data, err := s.Read(name, GlobalVariable)
	if IsNotExist(err) {
		return false, fmt.Errorf("no %s variable: no UEFI, or efivarfs not mounted", name)
	}
	if err != nil {
		return false, err
	}
	if len(data) != 1 {
		return false, fmt.Errorf("%s: %d bytes, not one", name, len(data))
	}
	return data[0] == 1, nil
}

// Risk says in one line what is wrong with this state; empty when Secure Boot is on and
// out of Setup Mode.
func (st SecureBootState) Risk() string {
	switch {
	case !st.Known:
		return "Secure Boot's state could not be read (" + st.Why + "): whether anything checks the boot loader and the kernel is unknown"
	case st.SetupMode:
		return "Secure Boot is in Setup Mode: nothing checks the boot loader and the kernel, and any root user can replace its keys"
	case !st.Enabled:
		return "Secure Boot is off: nothing checks the boot loader and the kernel, and PCR 7 records only that"
	}
	return ""
}
