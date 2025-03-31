package threshold

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/gebaolei/gmsm/sm2"
	"github.com/gebaolei/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// derivePartialPublicKey 从 SM2 私钥派生出部分公钥
func DerivePartialPublicKey(privateKey *sm2.PrivateKey) (*sm2.PublicKey, error) {
	// 获取曲线参数
	curve := sm2.P256Sm2()
	// 获取私钥的 d 值
	dA := privateKey.D
	// 计算 dA 的逆
	n := curve.Params().N
	dAInv := new(big.Int).ModInverse(dA, n)
	if dAInv == nil {
		return nil, fmt.Errorf("failed to compute inverse of private key")
	}
	// 计算部分公钥 P1 = dA_inv * G
	// G := curve.Params().G
	px, py := curve.ScalarBaseMult(dAInv.Bytes())
	// if err != nil {
	// 	return nil, err
	// }
	// 创建新的公钥
	publicKey := &sm2.PublicKey{
		Curve: curve,
		X:     px,
		Y:     py,
	}
	return publicKey, nil
}

// deriveCompletePublicKey 从自身私钥和对等方公钥派生出完整公钥
func DeriveCompletePublicKey(selfKey *sm2.PrivateKey, peerPubKey *sm2.PublicKey) (*sm2.PublicKey, error) {
	if selfKey == nil || peerPubKey == nil {
		return nil, fmt.Errorf("self key or peer public key is nil")
	}

	// 获取曲线参数
	curve := sm2.P256Sm2()
	// 获取自身私钥的 d1 值
	d1 := selfKey.D
	// 计算 d1 的逆
	n := curve.Params().N
	d1Inv := new(big.Int).ModInverse(d1, n)
	if d1Inv == nil {
		return nil, fmt.Errorf("failed to compute inverse of private key")
	}

	// 计算 d1_inv * P2
	PX, PY := curve.ScalarMult(peerPubKey.X, peerPubKey.Y, d1Inv.Bytes())

	// 获取基点 G
	GX := curve.Params().Gx
	GY := curve.Params().Gy
	// 计算 -G
	// 计算 -G（取负点）
	p := curve.Params().P
	GInvY := new(big.Int).Sub(p, GY)
	GInvY.Mod(GInvY, p)

	// 计算 P = d1_inv * P2 - G
	PX, PY = curve.Add(PX, PY, GX, GInvY)

	// 创建新的公钥
	publicKey := &sm2.PublicKey{
		Curve: curve,
		X:     PX,
		Y:     PY,
	}
	return publicKey, nil
}

// SM2ThresholdSign1Init 实现 SM2_THRESHOLD_sign1_init 功能
func sm2ThresholdSign1Init(ctx hash.Hash, pubKey *sm2.PublicKey, id []byte) (bool, error) {
	// 检查输入参数是否为 nil
	if pubKey == nil || id == nil {
		return false, errors.New("passed null parameter")
	}

	// // 计算 SM3 摘要大小
	// mdSize := sm3.Size

	// 生成 ZA
	za, err := sm2.ZA(pubKey, id)
	if err != nil {
		return false, err
	}

	// 初始化 SM3 哈希上下文
	ctx.Reset()

	// 更新 SM3 哈希上下文
	_, err = ctx.Write(za)
	if err != nil {
		return false, err
	}

	return true, nil
}

// SM2ThresholdSign1Update 实现 SM2_THRESHOLD_sign1_update 功能
func sm2ThresholdSign1Update(ctx hash.Hash, msg []byte) error {
	// 更新 SM3 哈希上下文
	_, err := ctx.Write(msg)
	if err != nil {
		return err
	}

	return nil
}

// SM2ThresholdSign1Final 实现 SM2_THRESHOLD_sign1_final 的功能
// func sm2ThresholdSign1Final(ctx hash.Hash) ([]byte, error) {
// 	// 计算最终的哈希值
// 	return ctx.Sum(nil), nil
// }

// SM2ThresholdSign1Oneshot 实现 SM2_THRESHOLD_sign1_oneshot 功能
func SM2ThresholdSign1Oneshot(pubKey *sm2.PublicKey, id []byte, msg []byte) ([]byte, error) {
	// 检查输入参数是否为 nil
	if pubKey == nil || id == nil || msg == nil {
		return nil, errors.New("passed null parameter")
	}

	// 创建 SM3 哈希上下文
	ctx := sm3.New()

	// 调用 SM2ThresholdSign1Init 进行初始化
	success, err := sm2ThresholdSign1Init(ctx, pubKey, id)
	if err != nil || !success {
		return nil, err
	}

	// 调用 SM2ThresholdSign1Update 进行消息更新
	err = sm2ThresholdSign1Update(ctx, msg)
	if err != nil {
		return nil, err
	}

	// var finalDigest []byte
	// // 调用 SM2ThresholdSign1Final 获取最终的哈希值
	// success, err = sm2ThresholdSign1Final(ctx, &finalDigest)
	// if err != nil {
	// 	return nil, err
	// }

	// return finalDigest, nil
	return ctx.Sum(nil), nil
}

// SM2ThresholdSign2 实现 SM2_THRESHOLD_sign2 功能
func SM2ThresholdSign2(key *sm2.PrivateKey, peerQ1 *sm2.PrivateKey, digest []byte) ([]byte, error) {
	// 检查输入参数是否为 nil
	if key == nil || peerQ1 == nil || digest == nil {
		return nil, errors.New("passed null parameter")
	}

	curve := sm2.P256Sm2()
	order := curve.Params().N
	dA := key.D

	// 将 digest 转换为大整数 e
	e := new(big.Int).SetBytes(digest)

	// 生成随机数 w2
	var w2 *big.Int
	var err error
	for {
		w2, err = rand.Int(rand.Reader, order)
		if err != nil {
			return nil, err
		}
		if w2.Sign() != 0 {
			break
		}
	}

	// 计算 dA 的逆
	dAInv := new(big.Int).ModInverse(dA, order)
	if dAInv == nil {
		return nil, errors.New("failed to compute inverse of dA")
	}

	// 计算 Q = [w2]G + dA^(-1) * Q1
	Qx, Qy := curve.ScalarBaseMult(w2.Bytes())
	Q1x, Q1y := peerQ1.X, peerQ1.Y
	Q1x, Q1y = curve.ScalarMult(Q1x, Q1y, dAInv.Bytes())
	Qx, Qy = curve.Add(Qx, Qy, Q1x, Q1y)

	// 获取 Q 的 x 坐标 x1
	x1 := Qx

	// 计算 r = (e + x1) mod n
	r := new(big.Int).Add(e, x1)
	r.Mod(r, order)

	// 计算 s1 = dA(r + w2) mod n
	s1 := new(big.Int).Add(r, w2)
	s1.Mul(s1, dA)
	s1.Mod(s1, order)

	// 创建签名对象
	// sig := &sm2.Signature{
	// 	R: r,
	// 	S: s1,
	// }

	// // 编码签名
	// sigBytes, err := sig.Encode()
	// if err != nil {
	// 	return nil, err
	// }

	// return sigBytes, nil
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s1)
	})
	return b.Bytes()
}

// SM2ThresholdSign3 实现 SM2_THRESHOLD_sign3 功能
func SM2ThresholdSign3(key *sm2.PrivateKey, tempKey *sm2.PrivateKey, sig2 []byte) ([]byte, error) {
	// 检查输入参数是否为 nil
	if key == nil || tempKey == nil || sig2 == nil {
		return nil, errors.New("passed null parameter")
	}

	curve := sm2.P256Sm2()
	order := curve.Params().N
	dA := key.D
	w1 := tempKey.D

	// // 解码 sig2
	// sig, err := sm2.DecodeSignature(sig2)
	// if err != nil {
	// 	return nil, err
	// }

	// r := sig.R
	// s1 := sig.S
	r, s1, err := sm2.SignDataToSignDigit(sig2)
	if err != nil {
		return nil, err
	}

	// 计算 s = (d1 * (s1 + w1) - r) mod n
	s := new(big.Int).Add(s1, w1)
	s.Mul(s, dA)
	s.Mod(s, order)
	s.Sub(s, r)
	s.Mod(s, order)

	// 更新签名对象
	// sig.S = s

	// 编码签名
	// sigBytes, err := sig.Encode()
	// if err != nil {
	// 	return nil, err
	// }

	// return sigBytes, nil
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}
