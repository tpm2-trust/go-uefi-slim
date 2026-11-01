package uki

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

// PCRSignature is one signature of a PCR policy as systemd writes it
// (systemd-measure sign --json, a UKI's .pcrsig):
//
//	{"pcrs": [11], "pkfp": "<hex>", "pol": "<hex>", "sig": "<base64>"}
//
// Pol is the policy digest; Sig, for an RSA key, PKCS #1 v1.5 over its SHA-256.
type PCRSignature struct {
	PCRs []int  `json:"pcrs"`
	Pkfp string `json:"pkfp"`
	Pol  string `json:"pol"`
	Sig  string `json:"sig"`
}

// PCRSignatures are those signatures by the bank's name ("sha256", "sha1").
type PCRSignatures map[string][]PCRSignature

// ParsePCRSignatures reads systemd's JSON; trailing NULs are allowed, as a
// section has them. Nothing in it is trusted: Find checks what it returns.
func ParsePCRSignatures(b []byte) (PCRSignatures, error) {
	var p PCRSignatures
	if err := json.Unmarshal(bytes.TrimRight(b, "\x00"), &p); err != nil {
		return nil, fmt.Errorf("not systemd's PCR signatures: %w", err)
	}
	return p, nil
}

// PCRSignatures reads the image's .pcrsig.
func (i *Image) PCRSignatures() (PCRSignatures, error) {
	b, err := i.SectionData(".pcrsig")
	if err != nil {
		return nil, err
	}
	return ParsePCRSignatures(b)
}

// Find is the signature for pcrs in bank over pol that verify accepts; nil when
// there is none. An entry that is malformed is passed over.
func (p PCRSignatures) Find(bank string, pcrs []int, pol []byte, verify func(sig []byte) error) []byte {
	for _, e := range p[bank] {
		if !slices.Equal(e.PCRs, pcrs) {
			continue
		}
		if got, err := hex.DecodeString(e.Pol); err != nil || !bytes.Equal(got, pol) {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil {
			continue
		}
		if verify(sig) == nil {
			return sig
		}
	}
	return nil
}
