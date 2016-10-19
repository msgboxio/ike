package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

type macFunc func(key, data []byte) []byte

func (macFunc) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func integrityTransform(cipherId uint16, cipher *simpleCipher) (*simpleCipher, bool) {
	macLen, truncLen, macFunc, ok := _integrityTransform(cipherId)
	if !ok {
		return nil, false
	}
	if cipher == nil {
		cipher = &simpleCipher{}
	}
	cipher.macFunc = macFunc
	cipher.macTruncLen = truncLen
	cipher.macLen = macLen
	cipher.AuthTransformId = protocol.AuthTransformId(cipherId)
	return cipher, true
}

func _integrityTransform(trfId uint16) (macLen, truncLen int, macFunc macFunc, ok bool) {
	switch protocol.AuthTransformId(trfId) {
	case protocol.AUTH_HMAC_SHA2_512_256:
		return 32 /* truncated */, sha512.Size256, hashMac(sha512.New, 32), true
	case protocol.AUTH_HMAC_SHA2_384_192:
		return 24 /* truncated */, sha512.Size384, hashMac(sha512.New384, 24), true
	case protocol.AUTH_HMAC_SHA2_256_128:
		return 16 /* truncated */, sha256.Size, hashMac(sha256.New, 16), true
	case protocol.AUTH_HMAC_SHA1_96:
		return 12 /* truncated */, sha1.Size, hashMac(sha1.New, 12), true
	default:
		return 0, 0, nil, false
	}
}

func hashMac(h func() hash.Hash, macLen int) macFunc {
	return func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)[:macLen]
	}
}

func verifyMac(key, b []byte, macLen int, macFn macFunc) error {
	l := len(b)
	msg := b[:l-macLen]
	msgMAC := b[l-macLen:]
	expectedMAC := macFn(key, msg)[:macLen]
	if !hmac.Equal(msgMAC, expectedMAC) {
		return errors.Errorf("HMAC verify failed: \n%svs\n%s",
			hex.Dump(msgMAC), hex.Dump(expectedMAC))
	}
	return nil
}
