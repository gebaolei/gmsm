// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package go-pkcs12 implements some of PKCS#12.
//
// This implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents. It is intended for decoding P12/PFX-stored
// certificates and keys for use with the crypto/tls package.
package pkcs12

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/gebaolei/gmsm/sm2"
x 	"github.com/gebaolei/gmsm/x509"
	"io/ioutil"
)

var (
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	oidFriendlyName     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
	oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

func (i *encryptedPrivateKeyInfo) SetData(data []byte) {
	i.EncryptedData = data
}

// PEM block types
const (
	certificateType = "CERTIFICATE"
	privateKeyType  = "PRIVATE KEY"
)

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		return errors.New("go-pkcs12: trailing data found")
	}
	return nil
}

// ConvertToPEM converts all "safe bags" contained in pfxData to PEM blocks.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, ErrIncorrectPassword
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)

	blocks := make([]*pem.Block, 0, len(bags))
	for _, bag := range bags {
		block, err := convertBag(&bag, encodedPassword)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	block := &pem.Block{
		Headers: make(map[string]string),
	}

	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		block.Headers[k] = v
	}

	switch {
	case bag.Id.Equal(oidCertBag):
		block.Type = certificateType
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, err
		}
		block.Bytes = certsData
	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		block.Type = privateKeyType

		key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			block.Bytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			block.Bytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	default:
		return nil, errors.New("don't know how to convert a safe bag of type " + bag.Id.String())
	}
	return block, nil
}

func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	isString := false

	switch {
	case attribute.Id.Equal(oidFriendlyName):
		key = "friendlyName"
		isString = true
	case attribute.Id.Equal(oidLocalKeyID):
		key = "localKeyId"
	case attribute.Id.Equal(oidMicrosoftCSPName):
		// This key is chosen to match OpenSSL.
		key = "Microsoft CSP Name"
		isString = true
	default:
		return "", "", errors.New("go-pkcs12: unknown attribute with OID " + attribute.Id.String())
	}

	if isString {
		if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return "", "", err
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return "", "", err
		}
	} else {
		var id []byte
		if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
			return "", "", err
		}
		value = hex.EncodeToString(id)
	}

	return key, value, nil
}

// DecodeAll extracts all certificates and a private key from pfxData.
func DecodeAll(pfxData []byte, password string) (privateKey interface{}, certificate []*x.Certificate, err error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, nil, err
	}

	//	if len(bags) != 2 {
	//		err = errors.New("go-pkcs12: expected exactly two safe bags in the PFX PDU")
	//		return
	//	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if certificate != nil {
				err = errors.New("go-pkcs12: expected exactly one certificate bag")
			}

			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs, err := x.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("go-pkcs12: expected exactly one certificate in the certBag")
				return nil, nil, err
			}
			certificate = append(certificate, certs[0])

		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			if privateKey != nil {
				err = errors.New("go-pkcs12: expected exactly one key bag")
			}

			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
				return nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, errors.New("go-pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, errors.New("go-pkcs12: private key missing")
	}

	return
}

// Decode extracts a certificate and private key from pfxData. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, nil, err
	}

	//	if len(bags) != 2 {
	//		err = errors.New("go-pkcs12: expected exactly two safe bags in the PFX PDU")
	//		return
	//	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if certificate != nil {
				err = errors.New("go-pkcs12: expected exactly one certificate bag")
			}

			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("go-pkcs12: expected exactly one certificate in the certBag")
				return nil, nil, err
			}
			certificate = certs[0]

		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			if privateKey != nil {
				err = errors.New("go-pkcs12: expected exactly one key bag")
			}

			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
				return nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, errors.New("go-pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, errors.New("go-pkcs12: private key missing")
	}

	return
}

func getSafeContents(p12Data, password []byte) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := new(pfxPdu)
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, errors.New("go-pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, errors.New("go-pkcs12: no MAC in data")
	}

	if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, err
	}

	if len(authenticatedSafe) != 2 {
		return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}

// Encode produces pfxData containing one private key, an end-entity certificate, and any number of CA certificates.
// It emulates the behavior of OpenSSL's PKCS12_create: it creates two SafeContents: one that's encrypted with RC2
// and contains the certificates, and another that is unencrypted and contains the private key shrouded with 3DES.
// The private key bag and the end-entity certificate bag have the LocalKeyId attribute set to the SHA-1 fingerprint
// of the end-entity certificate.
func Encode(privateKey interface{}, certificate *x.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, err
	}

	var pfx pfxPdu
	pfx.Version = 3

	var certFingerprint = sha1.Sum(certificate.Raw)
	var localKeyIdAttr pkcs12Attribute
	localKeyIdAttr.Id = oidLocalKeyID
	localKeyIdAttr.Value.Class = 0
	localKeyIdAttr.Value.Tag = 17
	localKeyIdAttr.Value.IsCompound = true
	if localKeyIdAttr.Value.Bytes, err = asn1.Marshal(certFingerprint[:]); err != nil {
		return nil, err
	}

	var certBags []safeBag
	var certBag *safeBag
	if certBag, err = makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIdAttr}); err != nil {
		return nil, err
	}
	certBags = append(certBags, *certBag)

	for _, cert := range caCerts {
		if certBag, err = makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	var keyBag safeBag
	keyBag.Id = oidPKCS8ShroundedKeyBag
	keyBag.Value.Class = 2
	keyBag.Value.Tag = 0
	keyBag.Value.IsCompound = true
	if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(privateKey, encodedPassword); err != nil {
		return nil, err
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIdAttr)

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(certBags, encodedPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents([]safeBag{keyBag}, nil); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pfx.MacData.Mac.Algorithm.Algorithm = oidSHA1
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = 1
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("go-pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.Id = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func makeSafeContents(bags []safeBag, password []byte) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if password == nil {
		ci.ContentType = oidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		randomSalt := make([]byte, 8)
		if _, err = rand.Read(randomSalt); err != nil {
			return
		}

		var algo pkix.AlgorithmIdentifier
		algo.Algorithm = oidPBEWithSHAAnd40BitRC2CBC
		if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
			return
		}

		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if err = pbEncrypt(&encryptedData.EncryptedContentInfo, data, password); err != nil {
			return
		}

		ci.ContentType = oidEncryptedDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(encryptedData); err != nil {
			return
		}
	}
	return
}
func SM2P12Encrypt(certificate *x.Certificate, pwd string, priv *sm2.PrivateKey, fileName string) error {
	pfxDataNew, err := Encode(priv, certificate, nil, pwd)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fileName, pfxDataNew, 0666)
	return err
}
func SM2P12Decrypt(fileName string, pwd string) (*x.Certificate, *sm2.PrivateKey, error) {
	pfxData, _ := ioutil.ReadFile(fileName)
	pv, cer, err := DecodeAll(pfxData, pwd)
	if err != nil {
		return nil, nil, err
	}
	switch k := pv.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case sm2.P256Sm2():
			sm2pub := &sm2.PublicKey{
				Curve: k.Curve,
				X:     k.X,
				Y:     k.Y,
			}
			sm2Pri := &sm2.PrivateKey{
				PublicKey: *sm2pub,
				D:         k.D,
			}
			if !k.IsOnCurve(k.X,k.Y) {
				return nil, nil, errors.New("error while validating SM2 private key: %v")
			}
			return cer[0], sm2Pri, nil
		}
	default:
		return nil, nil, errors.New("unexpected type for p12 private key")
	}
	return nil,nil,nil
}
