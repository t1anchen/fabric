package sw

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/t1anchen/gogmlib/sm2"
	"github.com/t1anchen/gogmlib/sm3"
	x509 "github.com/t1anchen/gogmlib/sm2/cert"
	"github.com/hyperledger/fabric/bccsp"
)

type sm2PrivateKey struct {
	privKey *sm2.PrivKey
	pubKey  *sm2.PubKey
}

// Bytes 给出私钥的字节流表示形式
//
// t1anchen: 对于此处仍参照 ecdsa 的实现，不排除以后需要实现之可能
func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("不支持此方法")
}

// SKI 返回这个密钥的 Subject Key Identifier
func (k *sm2PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	if k.pubKey == nil {
		return nil
	}

	raw := elliptic.Marshal(
		k.privKey.Curve,
		k.pubKey.X,
		k.pubKey.Y)

	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric 返回是否为对称密钥，在此处当然返回 False
func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

// Private 返回该密钥是否为私钥
func (k *sm2PrivateKey) Private() bool {
	return true
}

// PublicKey 返回相应的公钥
func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &sm2PublicKey{k.pubKey}, nil
}

// 实现基于 Key 接口的公钥
type sm2PublicKey struct {
	pubKey *sm2.PubKey
}

func (k *sm2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
 }

 // SKI 返回公钥的 Subject Key Identifier
func (k *sm2PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric 返回是否是对称密钥
func (k *sm2PublicKey) Symmetric() bool {
	return false
}

// Private 返回是否为私钥
func (k *sm2PublicKey) Private() bool {
	return false
}

// PublicKey 返回公钥
func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
