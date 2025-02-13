/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/gebaolei/gmsm/sm2"
)

func TestAnysign(t *testing.T) {
	certpem := `-----BEGIN CERTIFICATE-----
MIIGXjCCBgOgAwIBAgINKmdqIzHOjZMIDu8YYzAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTI0MTIyNDAyNTc1MloXDTI0MTIyNTAyNTc1MlowRjELMAkGA1UEBgwCQ04xFzAVBgNVBAsMDumTgei3r2Nh5rWL6K+VMR4wHAYDVQQDDBXnjovlpKfplKTvvIjmtYvor5XvvIkwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASAWFOudXIPRDGfTEqcge273CScDj/2gpdcM7m6VLZp60jXsbFvUeZ0ciaTWKm1/mQSO1mq3C2lQieD+OwnFBL9o4IEtzCCBLMwDgYDVR0PAQH/BAQDAgbAMAkGA1UdEwQCMAAwHQYDVR0OBBYEFAf4LJNEMmJgN1xNrp9svOg/FtRqMB8GA1UdIwQYMBaAFNbTCll0aA4P+8s9aW+YfPH9bs2jMD0GA1UdIAQ2MDQwMgYJKoEchu8yAgICMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vd3d3LmJqY2EuY24vQ1BTMIGOBgNVHR8EgYYwgYMwRqBEoEKGQGh0dHA6Ly9jcmwuYmpjYS5vcmcuY24vY3JsL1RydXN0X1NpZ25fU00yXzEvVHJ1c3RfU2lnbl9TTTJfMS5jcmwwOaA3oDWGM2h0dHA6Ly9jcmwuYmpjYS5vcmcuY24vY3JsL1RydXN0X1NpZ25fU00yXzEvMTAwLmNybDCCA4QGCiqBHIbvMgIBCQEEggN0ZXlKRGJHbGxiblJQVXlJNmV5SldaWEp6YVc5dUlqb2lOUzR3SUNoWGFXNWtiM2R6SUU1VUlERXdMakE3SUZkUFZ6WTBLU0JCY0hCc1pWZGxZa3RwZEM4MU16Y3VNellnS0V0SVZFMU1MQ0JzYVd0bElFZGxZMnR2S1NCRGFISnZiV1V2T0RZdU1DNDBNalF3TGpFNU9DQlRZV1poY21rdk5UTTNMak0ySWl3aVQxTkJjbU5vSWpvaU16SXZOalFpTENKVFpYSjJhV05sVUdGamF5STZJazV2Ym1VaUxDSkZaR2wwYVc5dUlqb2lUVzk2YVd4c1lTSXNJazVoYldVaU9pSlhaV2xZYVc1ZlYybHVNeklpZlN3aVFtbHZTR0Z6YUNJNlczc2lSbTl5YldGMElqb2lhVzFoWjJVdmNHNW5JaXdpU0dGemFFRnNaeUk2SWxOTk15SXNJa052Ym5SbGJuUWlPaUk0T0VaR05EUTBRVGhFT1RVME5qUTFRVVZHUkRBelF6WkVOek0xTVRjd01rRXdSRVE0TURJd05UaEJOREV6UWtFNE56bEJSRU01TWtRMFJqRkdOVVZDSWl3aVNHRnphRlI1Y0dVaU9pSm9ZWE5vTDNOamNtbHdkQ0o5TEhzaVJtOXliV0YwSWpvaWVtbHdJaXdpU0dGemFFRnNaeUk2SWxOTk15SXNJa052Ym5SbGJuUWlPaUkyTUVJMlJVSkNSVEZCT0RnNE9ESkJPRGM0UkVKRVFrVTBPVE0xTVRCRE56Z3pRelV6UmtGRU5UVTJOa05GUXprNE16YzJSalUwTkRReVJrVkVSamhDSWl3aVNHRnphRlI1Y0dVaU9pSm9ZWE5vTDNOamNtbHdkR1JoZEdFaWZWMHNJbEpoZDBoaGMyZ2lPaUpsUm05SmRHeDRkVXBPYUhoNmFsVlRhMnBPTmxWaVVVcFNhVEV5ZG1oRWNpdHdPV05xSzFWTVdFaHJQU0lzSWtoaGMyaGhiR2NpT2lKVFRUTWlMQ0pXWlhKemFXOXVJam9pTXk0eUlpd2lTVVJVZVhCbElqb2lNU0lzSWtsRVRuVnRZbVZ5SWpvaVRucGFORTVYZGxkRmMwc3ZZM0ZJTTBwWGJXOXRNRzkxTkd0VWJFeHJTSFl3ZEhsMlpsVjFiR3BsTUQwaWZRPT0wDAYIKoEcz1UBg3UFAANHADBEAiA6YkkDW0G5DracxS4seD3ALzxUh5eIsYAjJO2OWRncFwIgZbQiZpJu355X2TBg7x/TWQWVqtphNF9YBAXeG9VcoEw=
-----END CERTIFICATE-----`
	signdata := `MEUCIH3Lb3/XEwFnWcqbwzC5ygVxUUp4ab82k/dXRohzpFjBAiEAuqKEPBb8h2k66WWO/AECTd0+Jba3MAE7726xzB7KnjE=`
	cert, err := ReadCertificateFromPem([]byte(certpem))
	if err != nil {
		t.Fatal(err)
	}
	switch pubKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sm2pk := (*sm2.PublicKey)(pubKey)
		sign, _ := base64.StdEncoding.DecodeString(signdata)
		if sm2pk.Verify([]byte("ziyunb"), sign) {
			fmt.Printf("Verify ok\n")
		} else {
			t.Fatal("Verify failed")
		}
	}
}

func TestX509(t *testing.T) {
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
		fmt.Printf("CheckSignature ok\n")
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
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestVerifyBjcaMFSign(t *testing.T) {
	certPem := "-----BEGIN CERTIFICATE-----\nMIIC6jCCAo6gAwIBAgINKmetTfTOjZNjPt1wpjAMBggqgRzPVQGDdQUAMGcxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMTMwMQYDVQQLDCrnrb7lj5HmtYvor5Xor4HkuabkuI3og73nlKjkuo7nlJ/kuqfkuJrliqExFDASBgNVBAMMC1NNMua1i+ivlUNBMB4XDTI1MDIxMzAwNDIxMVoXDTI1MDIxMzEzNDIxMVowRDELMAkGA1UEBgwCQ04xJDAiBgNVBAoMG+atpui/m+WMuumdnuekvuS/neW+hemBh+WPkTEPMA0GA1UEAwwG5p2o6ZuEMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE9zl1D/1UpMkogXOXDWbDaM4dPAVeibPjL9HrtjWgdSGjqilBlxp0hQGQbTzcbvOk8VfirYxE/Woqt562EG8e0KOCAT4wggE6MA4GA1UdDwEB/wQEAwIGwDAJBgNVHRMEAjAAMIGFBgNVHR8EfjB8MEKgQKA+hjxodHRwOi8vY3JsLmJqY2Eub3JnLmNuL2NybC9TTTJZU1hTRUNPTkRDQS9TTTJZU1hTRUNPTkRDQS5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuYmpjYS5vcmcuY24vY3JsL1NNMllTWFNFQ09ORENBLzM5LmNybDAdBgNVHQ4EFgQU0QJacuo0kf3AefUFL1MwCGokHDswHwYDVR0jBBgwFoAU3fpmjDn5YMWtKZSC4Jmnfn5aOu4wPQYDVR0gBDYwNDAyBgkqgRyG7zICAgMwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly93d3cuYmpjYS5jbi9DUFMwFgYKKoEchu8yAgEJAQQITVRJek5EVTIwDAYIKoEcz1UBg3UFAANIADBFAiAtJs26h6bqo13tbSNOgx7Q8qG1wujZzxDbg53pxWv80gIhAPgVqP4G73jLXM1fmMPepRQH1fz5MEnpolCS5EJmVq28\n-----END CERTIFICATE-----"
	signValue := "MEUCIGas+thrYsSvxX8HiKIxllHXuqppE3wjGNds+6yLT0aaAiEAkd+g96CcXcsd97MONTouwopnqBFHny+F/NZB6hy/ZW4="
	hash := "9uJ6XZG5BGAwr8yj2HBBgmmGZFlHE3P/4NYklUm20EQ="
	raw_signValue, _ := base64.StdEncoding.DecodeString(signValue)

	r, s, err := sm2.SignDataToSignDigit(raw_signValue)
	if err != nil {
		t.Fatal(err)
	}

	if cert, err := ReadCertificateFromPem([]byte(certPem)); err != nil {
		t.Fatal(err)
	} else {
		pubkey := cert.PublicKey
		raw_hash, _ := base64.StdEncoding.DecodeString(hash)
		switch key := pubkey.(type) {
		case *ecdsa.PublicKey:
			var sm2pubkey sm2.PublicKey
			sm2pubkey.X = key.X
			sm2pubkey.Y = key.Y
			sm2pubkey.Curve = key.Curve
			if ok := sm2.Verify(&sm2pubkey, raw_hash, r, s); !ok {
				t.Fatal("verify failed")
			} else {
				fmt.Println("verify ok")
			}
		}
	}

}

func TestCreateRevocationList(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate rsa key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           privKey,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           privKey,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, rsa2048 key",
			key:  rsaPriv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SM2WithSM3,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}
			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				!parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}
