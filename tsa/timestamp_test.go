package tsa

import (
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/gebaolei/gmsm/sm2"
	"github.com/gebaolei/gmsm/x509"
)

var gmcert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAwSgAwIBAgIB/zAKBggqgRzPVQGDdTBHMQ0wCwYDVQQKEwRURVNUMRgw
FgYDVQQDEw9FbGFuIFRlc3QgR00gQ0ExDzANBgNVBCoTBkdvcGhlcjELMAkGA1UE
BhMCTkwwHhcNMjQwNzA1MDU1NDI1WhcNMjkwNzA1MDU1NDI1WjBiMQ0wCwYDVQQK
EwRURVNUMTMwMQYDVQQDDCrkuIDop4jmlbDlrZfnp5HmioDvvIjmsZ/oi4/vvInm
nInpmZDlhazlj7gxDzANBgNVBCoTBkdvcGhlcjELMAkGA1UEBhMCTkwwWTATBgcq
hkjOPQIBBggqgRzPVQGCLQNCAAS9bh+XNyeVPJLLmuYdeprz1quOON7Pye8QvfsQ
F4JQnSbONYwLUhkJf8Yi18GRW5et6/3n6iPBvUdfqapqM+75o4IBxDCCAcAwDgYD
VR0PAQH/BAQDAgeAMCYGA1UdJQQfMB0GCCsGAQUFBwMCBggrBgEFBQcDAQYCKgMG
A4ELATAPBgNVHRMBAf8EBTADAQH/MA8GA1UdIwQIMAaABAECAwQwXwYIKwYBBQUH
AQEEUzBRMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5leGFtcGxlLmNvbTAqBggr
BgEFBQcwAoYeaHR0cDovL2NydC5leGFtcGxlLmNvbS9jYTEuY3J0MEYGA1UdEQQ/
MD2CEHRlc3QuZXhhbXBsZS5jb22BEWdvcGhlckBnb2xhbmcub3JnhwR/AAABhxAg
AUhgAAAgAQAAAAAAAABoMA8GA1UdIAQIMAYwBAYCKgMwKgYDVR0eBCMwIaAfMA6C
DC5leGFtcGxlLmNvbTANggtleGFtcGxlLmNvbTBXBgNVHR8EUDBOMCWgI6Ahhh9o
dHRwOi8vY3JsMS5leGFtcGxlLmNvbS9jYTEuY3JsMCWgI6Ahhh9odHRwOi8vY3Js
Mi5leGFtcGxlLmNvbS9jYTEuY3JsMBYGAyoDBAQPZXh0cmEgZXh0ZW5zaW9uMA0G
A1UdDgQGBAQEAwIBMAoGCCqBHM9VAYN1A0cAMEQCIALOMwwscj00YXj0GqR4LUCe
A6dsMAw3V38XYvj3zXuUAiA5yK6L4UDSL9A5zT4mpY+eQ017JcYGvPEdRdIcB3oI
KA==
-----END CERTIFICATE-----`
var gmkey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg4u/a0jO0ZOcvEFgm
84pUoY2bZM2dX2YJORcZvZM8yMKgCgYIKoEcz1UBgi2hRANCAAS9bh+XNyeVPJLL
muYdeprz1quOON7Pye8QvfsQF4JQnSbONYwLUhkJf8Yi18GRW5et6/3n6iPBvUdf
qapqM+75
-----END PRIVATE KEY-----`

var rsacert = `-----BEGIN CERTIFICATE-----
MIIDoDCCAYgCAQEwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCQ04xEDAOBgNV
BAgMB0ppYW5nU3UxEDAOBgNVBAcMB05hbkppbmcxDTALBgNVBAoMBEVsYW4xFjAU
BgNVBAMMDUVsYW4gUlNBIENlcnQwHhcNMjMxMDI3MDMxMTExWhcNMzMxMDI0MDMx
MTExWjBYMQswCQYDVQQGEwJDTjEQMA4GA1UECAwHSmlhbmdTdTEQMA4GA1UEBwwH
TmFuSmluZzENMAsGA1UECgwERWxhbjEWMBQGA1UEAwwNRWxhbiBSU0EgQ2VydDCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArOZjJZO/qDjZlafQPdpcSq4B5VyU
lTLnA2d2rly0jD66gpExIwIRfuJtIwPoBEESo3tF/wp3BLeJF0kXQF1Gn64a/qo8
fxX3zDSEM0MjxpV/l2RcSVGn2RKEE5QPiBK5dm0J+hw4yj+diL+LvJLa1b1sASZV
2WuoCN5ATcaFWo8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAsMVEYJiyCKt3Lijw
1d7hRAbueApSuT4kRE/e9/dbD+B1XjKitW6Y1zWecho3iV3JxQKq5NwDx1kMQVmA
8E7cocka0dFvb8oOVuQ97P6rAPnzJbh77M03UhVtezwJjaNKWWWWKKLY9ENOmaeo
RPzq05LMvujG6a4l8TCASZTAph35fMNln9qN2YRYWWVxavaEMTNM9n3+uZanPvVU
Y4z/ZRiEiP2q7iS7qQznFiCNA9L6B8+SHAS9m8wleECc6IoaKrI4hm6pUaQxAZs6
pr4Rv/Tu42XiA9hPVwVKH5qy0U8L2kq5dOnTk2Dh5iPZMZR1lY2LvpichlRwhGCS
B+8keMjTChFU2pvgjjgjoaA4L8SlIV7DOAD92YDAYVZtWkqHSqA5zN9KSR3b/7+Y
o1cRcqCBJJkyDGMqf1B9RiHP3eVfWDrPU4DdVlW8N3dYoXNt+2ZKIqGM1LsBPAM8
kHZHONbUYg90tBowxJtw8xL/cV9Hmp+N/zTajMZXtCvyeNuJ1+HCJOoPfh6MzPtd
Ju/Hf9z9fxylPMZyhCemW4mpMxzrrfe+iip6y3gdh9wRZtzhJfhTRZ5FUzeVuGNK
bqxbuU0Zf/eqq2mmt+6N5QvghqXOlYQfevgBmQmpTk3LhbICFBi57fbHTt4apDnC
IZ5M2q8Jxt0UJ4iJTLO5nGNSBOE=
-----END CERTIFICATE-----`
var rsakey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCs5mMlk7+oONmVp9A92lxKrgHlXJSVMucDZ3auXLSMPrqCkTEj
AhF+4m0jA+gEQRKje0X/CncEt4kXSRdAXUafrhr+qjx/FffMNIQzQyPGlX+XZFxJ
UafZEoQTlA+IErl2bQn6HDjKP52Iv4u8ktrVvWwBJlXZa6gI3kBNxoVajwIDAQAB
AoGALpvw0FlzCiNBLKHPdk0eIhekdTMu7sWJFxbWHIzrMv9aAgan61sMYlshtpW/
/x2Xq7B4nxcwHHppn3hZp0U92y5rd9L39n9ODa31c3gmRZuzPIFpivS1fdKgYfza
R1LXrIKBInmze2U3deUaQNDthPaYd9lezc0uX3NjJuAFFAECQQDbAlI8jC8mCruW
KlK7o1wy8NcALYNCRIkc8Q8qKGiuAqho+AdE/tN5wYajEvrt+79KPm9cfxC7Et6W
Cw922ByPAkEAyhpdiXg+GIUVMoMuxKeHQ7l6/OjhtDViiLwWnC4myB4WIaoY0nlm
q9n2p929jh3nmePK/5pfFbGDdXPSu5niAQJBAKVJcjE6B1dpoDtrw7bTSoEznMAI
mViJCwYptC04BBDX9qwKDMp4m7f3Y5ptd63mYm8xAbDIQSM+0Xhh7pDd92cCQGQj
HCV5BotvpUkZ5ppZx5Ou21lkqjB4IxJM34cS9vRAtAaKGTJwJIcRwDz8iWdZOd/u
Fi7/dg1xnwkbElcRsAECQQDFS/T4FS9TVx4fJHYyW5txaX2fnGT6DA3PcM+JvWy+
i7WVB/SksMPKr6dGLJv89Kya9zJ2EzAhFLyfrQP3+wHP
-----END RSA PRIVATE KEY-----`

func TestGMCreateTimestampResponse(t *testing.T) {
	var cert *x509.Certificate
	var key *sm2.PrivateKey
	var err error
	if cert, err = x509.ReadCertificateFromPem([]byte(gmcert)); err != nil {
		t.Fatal("read cert error:", err.Error())
	}
	if key, err = x509.ReadPrivateKeyFromPem([]byte(gmkey), nil); err != nil {
		t.Fatal("read key error:", err.Error())
	}

	ts := time.Now()
	genTime := ts.UTC()
	duration, _ := time.ParseDuration("1s")

	tt := Timestamp{
		HashAlgorithm: x509.SM3,
		HashedMessage: []byte("123456789"),
		Time:          genTime,
		Nonce:         nil,
		// Policy:            req.TSAPolicyOID,
		Policy:            asn1.ObjectIdentifier{2, 4, 5, 6},
		Ordering:          true,
		Accuracy:          duration,
		Qualified:         false,
		AddTSACertificate: true,
	}
	if token, err := tt.CreateResponseWithOpts(cert, key, x509.SM3); err == nil {
		if resp, err := ParseResponse(token); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(resp.RawToken))
		} else {
			t.Fatal(err)
		}
	} else {
		t.Fatal(err)
	}
}

func TestRSACreateTimestampResponse(t *testing.T) {
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	var err error
	if cert, err = x509.ReadCertificateFromPem([]byte(rsacert)); err != nil {
		t.Fatal("read cert error:", err.Error())
	}

	tsaKeyPEMBlock, _ := pem.Decode([]byte(rsakey))
	key, err = x509.ParsePKCS1PrivateKey(tsaKeyPEMBlock.Bytes)
	if err != nil {
		t.Fatal("timestamp init key error")
	}

	ts := time.Now()
	genTime := ts.UTC()
	duration, _ := time.ParseDuration("1s")

	tt := Timestamp{
		HashAlgorithm: x509.SHA256,
		HashedMessage: []byte("123456789"),
		Time:          genTime,
		Nonce:         nil,
		// Policy:            req.TSAPolicyOID,
		Policy:            asn1.ObjectIdentifier{2, 4, 5, 6},
		Ordering:          true,
		Accuracy:          duration,
		Qualified:         false,
		AddTSACertificate: true,
	}
	if token, err := tt.CreateResponseWithOpts(cert, key, x509.SHA256); err == nil {
		if resp, err := ParseResponse(token); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(resp.RawToken))
		} else {
			t.Fatal(err)
		}
	} else {
		t.Fatal(err)
	}
}
