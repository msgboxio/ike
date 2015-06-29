package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/dgryski/go-camellia"

	"msgbox.io/log"
)

type cipherSuite struct {
	prfLen int
	prf    func(key, data []byte) []byte

	dhGroup *dhGroup

	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	// ka     func(version uint16) keyAgreement

	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(key, data []byte) []byte
	aead   func(key, fixedNonce []byte) cipher.AEAD
}

func newCipherSuite(trs []*SaTransform) *cipherSuite {
	cs := &cipherSuite{}
	for _, tr := range trs {
		switch tr.Transform.Type {
		case TRANSFORM_TYPE_DH:
			dhGroup, ok := kexAlgoMap[DhTransformId(tr.Transform.TransformId)]
			if !ok {
				log.Errorf("Missing dh transfom %s", tr.Transform.TransformId)
				return nil
			}
			cs.dhGroup = dhGroup
		case TRANSFORM_TYPE_PRF:
			// for hmac based prf, preferred key size is size of output
			cs.prfLen = sha256.Size
			cs.prf = macPrf(sha256.New)
		case TRANSFORM_TYPE_ENCR:
			// for block mode ciphers, equal to block length
			cs.cipher = cipherCamellia
			cs.ivLen = camellia.BlockSize
			cs.keyLen = int(tr.KeyLength) // from attribute; 32
		case TRANSFORM_TYPE_INTEG:
			cs.macLen = 16 // truncated
			cs.mac = hashMac(sha256.New, cs.macLen)
		}
	}
	return cs
}

func macPrf(h func() hash.Hash) func(key, data []byte) []byte {
	return func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherCamellia(key, iv []byte, isRead bool) interface{} {
	block, _ := camellia.New(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func hashMac(h func() hash.Hash, macLen int) func(key, data []byte) []byte {
	return func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)[:macLen]
	}
}
