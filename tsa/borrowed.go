package tsa

import (
	"encoding/asn1"

	"github.com/gebaolei/gmsm/x509"
)

// TODO(vanbroup): taken from "golang.org/x/crypto/ocsp"
// use directly from crypto/x509 when exported as suggested below.

var hashOIDs = map[x509.Hash]asn1.ObjectIdentifier{
	x509.SHA1:   x509.OIDDigestAlgorithmSHA1,
	x509.SHA256: x509.OIDDigestAlgorithmSHA256,
	x509.SHA384: x509.OIDDigestAlgorithmSHA384,
	x509.SHA512: x509.OIDDigestAlgorithmSHA512,
	x509.SM3:    x509.OIDDigestAlgorithmSM3,
}

// TODO(rlb): This is not taken from crypto/x509, but it's of the same general form.
func getHashAlgorithmFromOID(target asn1.ObjectIdentifier) x509.Hash {
	for hash, oid := range hashOIDs {
		if oid.Equal(target) {
			return hash
		}
	}
	return x509.Hash(0)
}

func getOIDFromHashAlgorithm(target x509.Hash) asn1.ObjectIdentifier {
	for hash, oid := range hashOIDs {
		if hash == target {
			return oid
		}
	}
	return nil
}

// TODO(vanbroup): taken from golang.org/x/crypto/x509
// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
