package x509

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"

	"github.com/gebaolei/gmsm/sm2"
)

var (
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDSignedAndEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	OIDDigestedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	OIDEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	OIDDigestAlgorithmSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OIDDigestAlgorithmDSASHA1       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDDigestAlgorithmSM3           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	OIDDigestAlgorithmSM3WithoutKey = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}

	// Signature Algorithms
	OIDSignatureRSA             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	OIDSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OIDSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	OIDSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	OIDEncryptionAlgorithmECDSAP256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDEncryptionAlgorithmECDSAP384  = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDEncryptionAlgorithmECDSAP521  = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	OIDEncryptionAlgorithmEDDSA25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// Encryption Algorithms
	OIDEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	OIDEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	OIDEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OIDEncryptionAlgorithmAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	OIDEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDEncryptionAlgorithmAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	OIDMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	OIDISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
	OIDTSTINFO                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDSIGNINGCERTIFICATEV2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// 《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》
	OIDSM2Data                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	OIDSM2SignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	OIDSM2EnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3}
	OIDSM2SignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 4}
	OIDSM2EncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 5}

	//SM2
	OIDSignatureSM2WithSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	OIDSignatureSM2WithSHA1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	OIDSignatureSM2WithSHA256 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
	OIDSignatureSM2           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	OIDSignatureDigestSM2     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
	OIDSignatureKeySM2        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}

	//SM9 Signed Data OIDs
	OIDSM9Data                = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 1}
	OIDSM9SignedData          = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 2}
	OIDSM9EnvelopedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 3}
	OIDSM9SignedEnvelopedData = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 4}
	OIDSM9EncryptedData       = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 4, 5}
	// SM9Sign-with-SM3
	OIDDigestAlgorithmSM9SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	// Signature Algorithms SM9-1
	OIDDigestEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}
	// Encryption Algorithms SM9-3
	OIDKeyEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

func getHashForOID(oid asn1.ObjectIdentifier) (Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1) || oid.Equal(OIDSignatureDSAWithSHA1) || oid.Equal(OIDSignatureECDSAWithSHA1) ||
		oid.Equal(OIDSignatureSM2WithSHA1) || oid.Equal(OIDSignatureRSA):
		return SHA1, nil
	case oid.Equal(OIDDigestAlgorithmSHA256) || oid.Equal(OIDSignatureDSAWithSHA256) || oid.Equal(OIDSignatureECDSAWithSHA256) ||
		oid.Equal(OIDSignatureSHA256WithRSA) || oid.Equal(OIDSignatureSM2WithSHA256):
		return SHA256, nil
	case oid.Equal(OIDDigestAlgorithmSHA384) || oid.Equal(OIDSignatureECDSAWithSHA384) || oid.Equal(OIDSignatureSHA384WithRSA):
		return SHA384, nil
	case oid.Equal(OIDDigestAlgorithmSHA512) || oid.Equal(OIDSignatureECDSAWithSHA512) || oid.Equal(OIDSignatureSHA512WithRSA):
		return SHA512, nil
	case oid.Equal(OIDDigestAlgorithmSM3) || oid.Equal(OIDDigestAlgorithmSM3WithoutKey) || oid.Equal(OIDSignatureSM2WithSM3):
		return SM3, nil
	}
	return Hash(0), ErrPKCS7UnsupportedDigestAlgorithm
}

// getOIDForEncryptionAlgorithm takes a private key or signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func getOIDForEncryptionAlgorithm(keyOrSigner interface{}, OIDDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	// _, ok := keyOrSigner.(*dsa.PrivateKey)
	// if ok {
	// 	return OIDDigestAlgorithmDSA, nil
	// }

	// signer, ok := keyOrSigner.(crypto.Signer)
	// if !ok {
	// 	return nil, fmt.Errorf("pkcs7: key does not implement crypto.Signer")
	// }
	switch k := keyOrSigner.(type) {
	case *dsa.PrivateKey, *dsa.PublicKey:
		return OIDDigestAlgorithmDSA, nil
	case *rsa.PublicKey, *rsa.PrivateKey:
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
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		switch {
		default:
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSM3):
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDSignatureECDSAWithSHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureECDSAWithSHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDSignatureECDSAWithSHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDSignatureECDSAWithSHA512, nil
		}

	case *sm2.PrivateKey, *sm2.PublicKey:
		switch {
		default:
			return OIDSignatureDigestSM2, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSM3):
			return OIDSignatureSM2WithSM3, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA1):
			return OIDSignatureSM2WithSHA1, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureSM2WithSHA256, nil
		}
	case *ed25519.PrivateKey, *ed25519.PublicKey:
		return OIDEncryptionAlgorithmEDDSA25519, nil
	case crypto.Signer:
		return getOIDForEncryptionAlgorithm(k.Public(), OIDDigestAlg)
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown key type %T", keyOrSigner)
}
