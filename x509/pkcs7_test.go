package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/gebaolei/gmsm/sm2"
)

func TestPKCS7SM2(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	pubkeyPem, err := WritePublicKeyToPem(pubKey)       // 生成公钥文件
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err = ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	if err != nil {
		t.Fatal(err)
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	reqPem, err := CreateCertificateRequestToPem(&templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	req, err := ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		t.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("Request CheckSignature error:%v", err)
	} else {
		t.Log("CheckSignature ok")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*sm2.PublicKey)
	certpem, err := CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	cert, err := ReadCertificateFromPem(certpem)
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Log("CheckSignature ok")
	}

	content := []byte("this is test")
	data, err := PKCS7EncryptSM2(content, []*Certificate{cert}, sm2.C1C3C2)
	if err != nil {
		t.Fatal("failed to PKCS7Encrypt ")
	}
	pk7Data, err := ParsePKCS7(data)

	if err != nil {
		t.Fatal("failed to ParsePKCS7 ")
	}
	decryptData, err := pk7Data.DecryptSM2(cert, priv, sm2.C1C3C2)
	if err != nil {
		t.Fatal("failed to PKCS7Decrypt ")
	}
	t.Log("decrypt success! data: ", string(decryptData))
}

var SignedDataRaw = `MIIEqgYKKoEcz1UGAQQCAqCCBJowggSWAgEBMQ8wDQYJKoEcz1UBgxEBBQAwZwYLKoZIhvcNAQkQAQSgWARWMFQCAQEGCCsGAQUFBwMIMC4wCgYIKoEcz1UBgxEEIG4PnhQ0TFQGoM9aO037Zl+H9Kdxox9+27XHKHSjKylXAgQF9eEBGA8yMDI0MTAxNDA4NTMxOFqgggLkMIIC4DCCAoWgAwIBAgIKGhAAAAAABB/fhzAKBggqgRzPVQGDdTBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0EwHhcNMjMxMjI1MTYwMDAwWhcNMzMwMTEwMTU1OTU5WjCBjDFFMEMGA1UEAww85Lit5Zu955S15L+h6IKh5Lu95pyJ6ZmQ5YWs5Y+45bi45bee5YiG5YWs5Y+45pe26Ze05oiz6K+B5LmmMTYwNAYDVQQKDC3kuK3lm73nlLXkv6HogqHku73mnInpmZDlhazlj7jluLjlt57liIblhazlj7gxCzAJBgNVBAYMAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEOCv8+WY/3XQFOcTqQaBwsUs+FHwlM7S6TODMpTXjy77XoVZcR4rAkJRKm0loPSxtPzkdIsTNKNjn+OcZF1Fuf6OCARQwggEQMB8GA1UdIwQYMBaAFB/mz9SPxSIql0opihXnFsmSNMS2MIGfBgNVHR8EgZcwgZQwYaBfoF2kWzBZMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0ExEzARBgNVBAMTCmNhMjFjcmwzNDkwL6AtoCuGKWh0dHA6Ly9jcmwuYmpjYS5vcmcuY24vY3JsL2NhMjFjcmwzNDkuY3JsMBEGCWCGSAGG+EIBAQQEAwIA/zALBgNVHQ8EBAMCA/gwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwEwYKKoEchu8yAgEBHgQFDAM2NTQwCgYIKoEcz1UBg3UDSQAwRgIhANOLWzxLbB5olg4u3jPfBwUOqifp0Dm+TQezWwtY64ZfAiEA834WVlowrWXHVSzh6B/4BJn62Xg8mwMuXHyFZYnUWrsxggEtMIIBKQIBATBSMEQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRcwFQYDVQQDDA5CZWlqaW5nIFNNMiBDQQIKGhAAAAAABB/fhzAMBggqgRzPVQGDEQUAoGswGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDEwMTQwODUzMThaMC8GCSqGSIb3DQEJBDEiBCAlLC8a+RK4126IZTyIpBV3qhXlXLZC66obkxHq1vLH0DANBgkqgRzPVQGCLQEFAARGMEQCIHmrF3HPvEQViO9GFcD4c7ukt/yTNNPP2u5Ju2RjD6BkAiABGelv3bmdmynGSc39XgA5WycgffxwI8aid//KKnOTmQ==`

func TestParsePKCS7(t *testing.T) {
	bys, err := base64.StdEncoding.DecodeString(SignedDataRaw)
	if err != nil {
		t.Fatal("raw data base64 decode error: ", err.Error())
	}
	p7, err := ParsePKCS7(bys)
	if err != nil {
		t.Fatal("rparse pkcsy error: ", err.Error())
	}
	if len(p7.Certificates) > 0 {
		if err := p7.Verify(); err != nil {
			t.Fatal("verify failed: ", err.Error())
		}
	}

}
