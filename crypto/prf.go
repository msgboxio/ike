package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"hash"

	"msgbox.io/ike/protocol"
)

type prfFunc func(key, data []byte) []byte

func prfTranform(prfId uint16) (prfLen int, prfFunc prfFunc, ok bool) {
	switch protocol.PrfTransformId(prfId) {
	case protocol.PRF_HMAC_SHA2_256:
		return sha256.Size, macPrf(sha256.New), true
	case protocol.PRF_HMAC_SHA1:
		return sha1.Size, macPrf(sha1.New), true
	default:
		return 0, nil, false
	}
}

func macPrf(h func() hash.Hash) prfFunc {
	return func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
}
