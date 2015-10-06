package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"hash"

	"msgbox.io/ike/protocol"
)

type macFunc func(key, data []byte) []byte

func integrityTransform(trfId uint16) (macLen, macKeyLength int, macFunc macFunc, ok bool) {
	switch protocol.AuthTransformId(trfId) {
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
