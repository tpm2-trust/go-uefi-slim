// Package pkcs7 builds and reads the PKCS#7 (RFC 2315) SignedData that UEFI
// uses: one signer, SHA-256, RSA, signed attributes, the signer's
// certificate included. Signed variable updates carry it detached and
// without the ContentInfo around it; Authenticode carries its content
// (SpcIndirectDataContent) inside, wrapped in a ContentInfo.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

var (
	OIDData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// AlgorithmIdentifier is X.509's.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// SHA256 is the digest algorithm, with NULL parameters as Authenticode and
// the firmware write it.
var SHA256 = AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version                   int
	IssuerAndSerial           issuerAndSerial
	DigestAlgorithm           AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// Options of Sign.
type Options struct {
	// ContentType is the content's type: OIDData for a signed variable,
	// SPC_INDIRECT_DATA for Authenticode.
	ContentType asn1.ObjectIdentifier
	// Content is put inside, DER; nil leaves it detached.
	Content []byte
	// Digested is what the message digest attribute is over: the content's
	// value octets (Authenticode), or the data a detached signature covers.
	Digested []byte
	// SigningTime adds the signing time attribute when not zero.
	SigningTime time.Time
}

// Sign is a SignedData, DER, without a ContentInfo around it.
func Sign(signer crypto.Signer, cert *x509.Certificate, o Options) ([]byte, error) {
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("UEFI signatures are RSA: the key is not")
	}
	digest := sha256.Sum256(o.Digested)
	attrs, err := attributes(o, digest[:])
	if err != nil {
		return nil, err
	}
	// The signature is over the attributes as a SET (tag 0x31), though they
	// sit in the SignerInfo as [0] IMPLICIT.
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(set)
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{ContentType: o.ContentType}
	if o.Content != nil {
		if ci.Content, err = explicit0(o.Content); err != nil {
			return nil, err
		}
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{SHA256},
		ContentInfo:      ci,
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos: []signerInfo{{
			Version:                   1,
			IssuerAndSerial:           issuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber},
			DigestAlgorithm:           SHA256,
			AuthenticatedAttributes:   asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
			DigestEncryptionAlgorithm: AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
			EncryptedDigest:           sig,
		}},
	}
	return asn1.Marshal(sd)
}

// attributes is the DER of the signed attributes, sorted as a SET OF must
// be.
func attributes(o Options, digest []byte) ([]byte, error) {
	var list [][]byte
	add := func(t asn1.ObjectIdentifier, v any) error {
		val, err := asn1.Marshal(v)
		if err != nil {
			return err
		}
		a, err := asn1.Marshal(attribute{Type: t, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: val}})
		list = append(list, a)
		return err
	}
	if err := add(oidAttrContentType, o.ContentType); err != nil {
		return nil, err
	}
	if !o.SigningTime.IsZero() {
		if err := add(oidAttrSigningTime, o.SigningTime.UTC()); err != nil {
			return nil, err
		}
	}
	if err := add(oidAttrMessageDigest, digest); err != nil {
		return nil, err
	}
	slices.SortFunc(list, bytes.Compare)
	return bytes.Join(list, nil), nil
}

// explicit0 is der under an explicit [0], as a value Marshal writes as it
// is (it ignores a field's explicit tag for a RawValue's FullBytes).
func explicit0(der []byte) (asn1.RawValue, error) {
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der})
	return asn1.RawValue{FullBytes: b}, err
}

// Wrap puts a SignedData into a ContentInfo.
func Wrap(sd []byte) ([]byte, error) {
	c, err := explicit0(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{ContentType: OIDSignedData, Content: c})
}

// Unwrap takes a SignedData out of its ContentInfo; one without is
// returned as it is.
func Unwrap(der []byte) ([]byte, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err == nil && len(rest) == 0 && ci.ContentType.Equal(OIDSignedData) {
		return ci.Content.Bytes, nil // the RawValue is the [0]; Bytes are what it holds
	}
	return der, nil
}

// Signed is a parsed SignedData.
type Signed struct {
	ContentType asn1.ObjectIdentifier
	// Content is the content inside, DER (nil when detached).
	Content []byte
	// Certificates are those it carries.
	Certificates []*x509.Certificate
	signer       signerInfo
}

// Parse reads a SignedData, with or without its ContentInfo.
func Parse(der []byte) (*Signed, error) {
	der, err := Unwrap(der)
	if err != nil {
		return nil, err
	}
	var sd signedData
	rest, err := asn1.Unmarshal(der, &sd)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#7 SignedData: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("data after the SignedData")
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%d signers, not one", len(sd.SignerInfos))
	}
	s := &Signed{ContentType: sd.ContentInfo.ContentType, signer: sd.SignerInfos[0]}
	if len(sd.ContentInfo.Content.FullBytes) > 0 {
		s.Content = sd.ContentInfo.Content.Bytes
	}
	if len(sd.Certificates.Bytes) > 0 {
		s.Certificates, err = x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Signer is the certificate of the signer among those carried; nil when it
// is not carried.
func (s *Signed) Signer() *x509.Certificate {
	for _, c := range s.Certificates {
		if bytes.Equal(c.RawIssuer, s.signer.IssuerAndSerial.Issuer.FullBytes) && c.SerialNumber.Cmp(s.signer.IssuerAndSerial.Serial) == 0 {
			return c
		}
	}
	return nil
}

// Verify checks that the signer signed digested (the data the message
// digest attribute covers) with cert's key, and that cert is the
// signer's - or, for trust, that the signer's certificate is signed by
// trust.
func (s *Signed) Verify(digested []byte, trust *x509.Certificate) error {
	if !s.signer.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		return errors.New("not a SHA-256 signature")
	}
	signer := s.Signer()
	if signer == nil {
		return errors.New("the signer's certificate is not carried")
	}
	if len(s.signer.AuthenticatedAttributes.Bytes) == 0 {
		// No signed attributes (efitools' sign-efi-sig-list): the
		// signature is over the data itself.
		if err := signer.CheckSignature(x509.SHA256WithRSA, digested, s.signer.EncryptedDigest); err != nil {
			return fmt.Errorf("the signature: %w", err)
		}
		return trusted(signer, trust)
	}
	var md []byte
	rest := s.signer.AuthenticatedAttributes.Bytes
	for len(rest) > 0 {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return err
		}
		if a.Type.Equal(oidAttrMessageDigest) {
			if _, err := asn1.Unmarshal(a.Values.Bytes, &md); err != nil {
				return err
			}
		}
	}
	want := sha256.Sum256(digested)
	if !bytes.Equal(md, want[:]) {
		return errors.New("the message digest does not match")
	}
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: s.signer.AuthenticatedAttributes.Bytes})
	if err != nil {
		return err
	}
	if err := signer.CheckSignature(x509.SHA256WithRSA, set, s.signer.EncryptedDigest); err != nil {
		return fmt.Errorf("the signature: %w", err)
	}
	return trusted(signer, trust)
}

// trusted: signer is trust, or signed by it.
func trusted(signer, trust *x509.Certificate) error {
	if trust == nil || signer.Equal(trust) {
		return nil
	}
	if err := signer.CheckSignatureFrom(trust); err != nil {
		return fmt.Errorf("signed by %s, not by the trusted %s", signer.Subject, trust.Subject)
	}
	return nil
}
