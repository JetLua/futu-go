package futu

import (
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/keypair"
)

type RSA struct {
	kp *keypair.RsaKeyPair
}

func NewRSA(pbkStr, prkStr string) (*RSA, error) {
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(keypair.PKCS8)
	kp.SetPadding(keypair.PKCS1v15)
	err := kp.SetPublicKey([]byte(pbkStr))
	if err != nil {
		return nil, err
	}
	err = kp.SetPrivateKey([]byte(prkStr))
	if err != nil {
		return nil, err
	}
	return &RSA{kp}, nil
}

func (r *RSA) Encrypt(data []byte) []byte {
	return dongle.Encrypt.FromBytes(data).ByRsa(r.kp).ToRawBytes()
}

func (r *RSA) Decrypt(data []byte) []byte {
	return dongle.Decrypt.FromRawBytes(data).ByRsa(r.kp).ToBytes()
}

type AES struct {
	c *cipher.AesCipher
}

func NewAES(key string, iv string) *AES {
	c := cipher.NewAesCipher(cipher.CBC)
	c.SetKey([]byte(key))
	c.SetIV([]byte(iv))
	c.SetPadding(cipher.PKCS7)
	return &AES{c: c}
}

// aes-128-cbc encrypt
func (a *AES) Encrypt(raw []byte) []byte {
	return dongle.Encrypt.FromBytes(raw).ByAes(a.c).ToRawBytes()
}

// aes-128-cbc decrypt
func (a *AES) Decrypt(raw []byte) []byte {
	return dongle.Decrypt.FromRawBytes(raw).ByAes(a.c).ToBytes()
}
