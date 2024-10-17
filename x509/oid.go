package x509

import "encoding/asn1"

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
	OIDSMSignedData           = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}

	// Digest Algorithms
	OIDDigestAlgorithmSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OIDDigestAlgorithmDSASHA1       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDDigestAlgorithmECDSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDDigestAlgorithmECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDDigestAlgorithmECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDDigestAlgorithmECDSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
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

	OIDSignatureSM2WithSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	OIDSignatureSM2WithSHA1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	OIDSignatureSM2WithSHA256 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
	OIDSignatureDSASM2        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}

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
)

var (
// Signature Algorithms
// OIDSignatureRSA             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
// OIDSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
// OIDSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
// OIDSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
// OIDSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
// OIDSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
// OIDSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
// OIDSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
// OIDSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
// OIDSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
// OIDSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
// OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
// OIDSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
// OIDSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

// OIDEncryptionAlgorithmECDSAP256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
// OIDEncryptionAlgorithmECDSAP384  = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
// OIDEncryptionAlgorithmECDSAP521  = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
// OIDEncryptionAlgorithmEDDSA25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

// OIDSignatureSM2WithSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
// OIDSignatureSM2WithSHA1   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
// OIDSignatureSM2WithSHA256 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 503}
// OIDSignatureDSASM2        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
//	oidSignatureSM3WithRSA      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}

// Encryption Algorithms
// OIDEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
// OIDEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
// OIDEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
// OIDEncryptionAlgorithmAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
// OIDEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
// OIDEncryptionAlgorithmAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

// Digest Algorithms
// OIDDigestAlgorithmSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
// OIDDigestAlgorithmSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
// OIDDigestAlgorithmSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
// OIDDigestAlgorithmSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
// OIDDigestAlgorithmDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
// OIDDigestAlgorithmDSASHA1       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
// OIDDigestAlgorithmECDSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
// OIDDigestAlgorithmECDSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
// OIDDigestAlgorithmECDSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
// OIDDigestAlgorithmECDSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
// OIDDigestAlgorithmSM3           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
// OIDDigestAlgorithmSM3WithoutKey = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}

// OIDMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

// // oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
// // but it's specified by ISO. Microsoft's makecert.exe has been known
// // to produce certificates with this OID.
// OIDISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)
