package x509

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // for crypto.SHA1
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/gebaolei/gmsm/sm2"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.156.10197.6.1.4.2.1), Signed Data (1.2.156.10197.6.1.4.2.2),
// and Enveloped Data are supported (1.2.156.10197.6.1.4.2.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// ParsePKCS7 decodes a DER encoded PKCS7.
func ParsePKCS7(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(OIDSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDSMSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return ParseCertificates(val.Bytes)
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

// Verify checks the signatures of a PKCS7 object
// WARNING: Verify does not check signing time or verify certificate chains at
// this time.
func (p7 *PKCS7) Verify() (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo) error {
	signedData := p7.Content
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	// fmt.Println("===== hash algo=====:", hash)
	if len(signer.AuthenticatedAttributes) > 0 {
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		// TODO(shengzhi): Optionally verify certificate chain
		// TODO(shengzhi): Optionally verify signingTime against certificate NotAfter/NotBefore
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("pkcs7: No certificate for signer")
	}

	algo := getSignatureAlgorithmByHash(hash, signer.DigestEncryptionAlgorithm.Algorithm)
	if algo == UnknownSignatureAlgorithm {
		return ErrPKCS7UnsupportedAlgorithm
	}
	return cert.CheckSignature(algo, signedData, signer.EncryptedDigest)
}

func getSignatureAlgorithmByHash(hash Hash, oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch hash {
	case SM3:
		switch {
		case oid.Equal(OIDSignatureSM2WithSM3):
			return SM2WithSM3
		case oid.Equal(OIDSignatureDSASM2):
			return SM21
		}
	case SHA256:
		switch {
		case oid.Equal(OIDSignatureDSASM2):
			return SM2WithSHA256
		case oid.Equal(OIDSignatureSHA256WithRSA):
			return SHA256WithRSA
		}
	case SHA512:
		switch {
		case oid.Equal(OIDSignatureSHA512WithRSA):
			return SHA256WithRSA
		}
	case SHA384:
		switch {
		case oid.Equal(OIDSignatureSHA384WithRSA):
			return SHA384WithRSA
		}
	case SHA1:
		switch {
		case oid.Equal(OIDSignatureDSASM2):
			return SM2WithSHA256
		case oid.Equal(OIDSignatureDSAWithSHA256):
			return SHA256WithRSA
		}
	}
	return UnknownSignatureAlgorithm
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(encodedAttributes, &raw)
	if err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

var (
	oidDigestAlgorithmSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func getCertFromCertsByIssuerAndSerial(certs []*Certificate, ias issuerAndSerial) *Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func getHashForOID(oid asn1.ObjectIdentifier) (Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1):
		return SHA1, nil
	case oid.Equal(OIDDigestAlgorithmSHA256):
		return SHA256, nil
	case oid.Equal(OIDDigestAlgorithmSHA384):
		return SHA384, nil
	case oid.Equal(OIDDigestAlgorithmSHA512):
		return SHA512, nil
	case oid.Equal(OIDDigestAlgorithmSM3):
		return SM3, nil
	case oid.Equal(OIDDigestAlgorithmSM3WithoutKey):
		return SM3, nil
	}
	return Hash(0), ErrPKCS7UnsupportedDigestAlgorithm
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// ErrPKCS7UnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrPKCS7UnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")
var ErrPKCS7UnsupportedDigestAlgorithm = errors.New("pkcs7: cannot digest data: only sha1, sha256, sha384, sha512 and sm3 supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *Certificate, pk crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	if priv := pk.(*rsa.PrivateKey); priv != nil {
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	fmt.Printf("Unsupported Private Key: %v\n", pk)
	// TODO: SM decript
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func (p7 *PKCS7) DecryptSM2(cert *Certificate, pk crypto.PrivateKey, mode int) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}

	if priv := pk.(*sm2.PrivateKey); priv != nil {
		var contentKey []byte
		contentKey, err := sm2.Decrypt(priv, recipient.EncryptedKey, mode)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}

	fmt.Printf("Unsupported Private Key: %v\n", pk)
	// TODO: SM decript
	return nil, ErrPKCS7UnsupportedAlgorithm
}

var oidEncryptionAlgorithmDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
var oidEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
var oidEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
var oidEncryptionAlgorithmAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
var oidEncryptionAlgorithmAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(oidEncryptionAlgorithmDESCBC) &&
		!alg.Equal(oidEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		fmt.Printf("Unsupported Content Encryption Algorithm: %s\n", alg)
		return nil, ErrPKCS7UnsupportedAlgorithm
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(oidEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(oidEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(oidEncryptionAlgorithmAES256CBC):
		fallthrough
	case alg.Equal(oidEncryptionAlgorithmAES128GCM), alg.Equal(oidEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}

func isCertMatchForIssuerAndSerial(cert *Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.RawIssuer, ias.IssuerName.FullBytes) == 0
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd                  signedData
	certs               []*Certificate
	data, messageDigest []byte
	digestOid           asn1.ObjectIdentifier
	encryptionOid       asn1.ObjectIdentifier
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute
	SkipCertificates        bool
}

// NewSignedData initializes a SignedData with content
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: OIDData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidDigestAlgorithmSHA1,
	}
	h := crypto.SHA1.New()
	h.Write(data)
	md := h.Sum(nil)
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	return &SignedData{sd: sd, messageDigest: md, data: data, digestOid: OIDDigestAlgorithmSHA1}, nil
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	sd.digestOid = d
}

// SetEncryptionAlgorithm sets the encryption algorithm to be used in the signing process.
//
// This should be called before adding signers
func (sd *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
	sd.encryptionOid = d
}

// SetContentType sets the content type of the SignedData. For example to specify the
// content type of a time-stamp token according to RFC 3161 section 2.4.2.
func (sd *SignedData) SetContentType(contentType asn1.ObjectIdentifier) {
	sd.sd.ContentInfo.ContentType = contentType
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData {
	return &sd.sd
}

// getOIDForEncryptionAlgorithm takes a private key or signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func getOIDForEncryptionAlgorithm(keyOrSigner interface{}, OIDDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	_, ok := keyOrSigner.(*dsa.PrivateKey)
	if ok {
		return OIDDigestAlgorithmDSA, nil
	}

	signer, ok := keyOrSigner.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkcs7: key does not implement crypto.Signer")
	}
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		switch {
		default:
			return OIDSignatureRSA, nil
		case OIDDigestAlg.Equal(OIDSignatureRSA):
			return OIDSignatureRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDSignatureSHA1WithRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureSHA256WithRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDSignatureSHA384WithRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDSignatureSHA512WithRSA, nil
		}
	case *ecdsa.PublicKey:
		switch {
		default:
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSM3):
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDDigestAlgorithmECDSASHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDDigestAlgorithmECDSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDDigestAlgorithmECDSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDDigestAlgorithmECDSASHA512, nil
		}

	case *sm2.PublicKey:
		switch {
		default:
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSM3):
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDSignatureSM2WithSHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureSM2WithSHA256, nil
		}
	case ed25519.PublicKey:
		return OIDEncryptionAlgorithmEDDSA25519, nil
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown key type %T", signer.Public())
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *Certificate, parents []*Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent. The signer can
// either be a crypto.Signer or crypto.PrivateKey.
func (sd *SignedData) AddSigner(ee *Certificate, keyOrSigner interface{}, config SignerInfoConfig) error {
	var parents []*Certificate
	return sd.AddSignerChain(ee, keyOrSigner, parents, config)
}

// AddSigner signs attributes about the content and adds certificate to payload
func (sd *SignedData) AddSignerChain(cert *Certificate, pkey crypto.PrivateKey, parents []*Certificate, config SignerInfoConfig) error {
	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias issuerAndSerial
	ias.SerialNumber = cert.SerialNumber
	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	} else {
		err := verifyPartialChain(cert, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
	)
	hash, err := getHashForOID(sd.digestOid)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)
	signatureOid, err := getOIDForEncryptionAlgorithm(pkey, sd.digestOid)
	if err != nil {
		return err
	}

	attrs := &attributes{}
	attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(OIDAttributeMessageDigest, sd.messageDigest)
	attrs.Add(OIDAttributeSigningTime, time.Now().UTC())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}
	unsignedAttrs := &attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}
	// create signature of signed attributes
	signature, err := signAttributes(finalAttrs, pkey, hash)
	if err != nil {
		return err
	}
	signerInfo := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		UnauthenticatedAttributes: finalUnsignedAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	if !config.SkipCertificates {
		sd.certs = append(sd.certs, cert)
		if len(parents) > 0 {
			sd.certs = append(sd.certs, parents...)
		}
	}
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signerInfo)
	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: OIDData}
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func cert2issuerAndSerial(cert *Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey, hash Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(attrBytes)
	hashed := h.Sum(nil)
	// switch priv := pkey.(type) {
	// case *rsa.PrivateKey:
	// 	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed)
	// }
	// return nil, ErrPKCS7UnsupportedAlgorithm

	// dsa doesn't implement crypto.Signer so we make a special case
	// https://github.com/golang/go/issues/27889
	switch pkey := pkey.(type) {
	case *dsa.PrivateKey:
		r, s, err := dsa.Sign(rand.Reader, pkey, hashed)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(dsaSignature{r, s})
	case *sm2.PrivateKey:
		return pkey.Sign(rand.Reader, attrBytes, nil)
	}

	signer, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkcs7: private key does not implement crypto.Signer")
	}

	// special case for Ed25519, which hashes as part of the signing algorithm
	_, ok = signer.Public().(ed25519.PublicKey)
	if ok {
		return signer.Sign(rand.Reader, attrBytes, crypto.Hash(0))
	}

	return signer.Sign(rand.Reader, hashed, hash)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: OIDData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}

const (
	EncryptionAlgorithmDESCBC = iota
	EncryptionAlgorithmAES128GCM
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC and AES-128-GCM supported")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAES128GCM(content []byte) ([]byte, *encryptedContentInfo, error) {
	// Create AES key and nonce
	key := make([]byte, 16)
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEncryptionAlgorithmAES128GCM,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte) ([]byte, *encryptedContentInfo, error) {
	// Create DES key & CBC IV
	key := make([]byte, 8)
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// The algorithm used to perform encryption is determined by the current value
// of the global ContentEncryptionAlgorithm package variable. By default, the
// value is EncryptionAlgorithmDESCBC. To use a different algorithm, change the
// value before calling Encrypt(). For example:
//
//	ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func PKCS7Encrypt(content []byte, recipients []*Certificate) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)

	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidEncryptionAlgorithmRSA,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *Certificate) ([]byte, error) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func PKCS7EncryptSM2(content []byte, recipients []*Certificate, mode int) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)

	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKeySM2(key, recipient, mode)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDSignatureSM2WithSM3,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func encryptKeySM2(key []byte, recipient *Certificate, mode int) ([]byte, error) {
	if pub := recipient.PublicKey.(*ecdsa.PublicKey); pub != nil {
		pubkey := &sm2.PublicKey{}
		pubkey.Curve = pub.Curve
		pubkey.Y = pub.Y
		pubkey.X = pub.X
		return sm2.Encrypt(pubkey, key, rand.Reader, mode)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}
