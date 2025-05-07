package threshold

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/gebaolei/gmsm/sm2"
	"github.com/gebaolei/gmsm/x509"
)

func TestXietongJava(t *testing.T) {
	pk_pem := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgMStD3E1mHLdaicTS
tpFbtjkiNTqvnvQH2+539SX0ocigCgYIKoEcz1UBgi2hRANCAAQyDAjeG750iTGL
gnmIm2H9yGVUZyU55f1/SaKNJ6aGIkX1pCpv4mE75y6rn2/HjhG5rTDIx1/HVb3c
qGbi0lEb
-----END PRIVATE KEY-----`
	pk, err := x509.ReadPrivateKeyFromPem([]byte(pk_pem), nil)
	if err != nil {
		t.Fatal(err)
	}

	pubk, err := DerivePartialPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	pubk_str, _ := x509.WritePublicKeyToPem(pubk)
	fmt.Println(string(pubk_str))
	pubk_hex := x509.WritePublicKeyToHex(pubk)
	fmt.Println(pubk_hex)
	// fmt.Println(x509.WritePublicKeyToHex(pubk))

	pubk2_str := `0428f6baad64e1d350fde5871bd335363347537cab6e4353bd19e679f4605c225c0d2d4e8497e2611532b6c696901a42ec79886de052721245b5a016ae132d3b21`
	pubk2, err := x509.ReadPublicKeyFromHex(pubk2_str)
	if err != nil {
		t.Fatal(pubk2)
	}
	complete_pubk, err := DeriveCompletePublicKey(pk, pubk2)
	if err != nil {
		t.Fatal(pubk2)
	}
	fmt.Println(x509.WritePublicKeyToHex(complete_pubk))
	complete_str, _ := x509.WritePublicKeyToPem(complete_pubk)
	fmt.Println(string(complete_str))

	digest, err := SM2ThresholdSign1Oneshot(complete_pubk, []byte("1234567812345678"), []byte("gebaolei"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("digest hex: ", hex.EncodeToString(digest))

}
func TestXietong(t *testing.T) {
	// 生成客户端私钥
	pk1, _ := sm2.GenerateKey(nil)

	pk1_str, _ := x509.WritePrivateKeyToPem(pk1, nil)
	fmt.Println("pk1: ", string(pk1_str))
	// pubk1, err := DerivePartialPublicKey(pk1)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// 生成服务端私钥
	pk2, _ := sm2.GenerateKey(nil)

	pk2_str, _ := x509.WritePrivateKeyToPem(pk2, nil)
	fmt.Println("pk2: ", string(pk2_str))

	// 导出服务端部分公钥，交给客户端 （客户端也应该要到处自己的部分私钥，交给服务端）
	pubk2, err := DerivePartialPublicKey(pk2)
	if err != nil {
		t.Fatal(err)
	}

	// 客户端计算最终的公钥，(服务端可以使用pk2， pubk1也会生成最终公钥， 两方的最终公钥都是一样的（代码省略了）)
	complate_pubk, err := DeriveCompletePublicKey(pk1, pubk2)
	if err != nil {
		t.Fatal(err)
	}
	complate_pubk_str, _ := x509.WritePublicKeyToPem(complate_pubk)
	fmt.Println("complete pubkey: ", string(complate_pubk_str))

	// 生成随机私钥 双方持有, 用来计算hash
	tmp_pk, _ := sm2.GenerateKey(nil)

	// 生成hash （客户端或者服务端都可）
	digest, err := SM2ThresholdSign1Oneshot(complate_pubk, []byte("1234567812345678"), []byte("gebaolei"))
	if err != nil {
		t.Fatal(err)
	}

	// 服务端计算签名值1
	sign1, err := SM2ThresholdSign2(pk2, tmp_pk, digest)
	if err != nil {
		t.Fatal(err)
	}

	// 客户端计算最终签名值
	finsign, err := SM2ThresholdSign3(pk1, tmp_pk, sign1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(finsign))

	// 验签， 使用最终生成的公钥验签
	ok := complate_pubk.Verify([]byte("gebaolei"), finsign)
	if ok != true {
		t.Fatal("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
}
