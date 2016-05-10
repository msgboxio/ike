package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/msgboxio/ike/protocol"
)

// Pseudo Random Function
type Prf struct {
	Apply  func(key, data []byte) []byte
	Length int
	name   string
}

func (p *Prf) MarshalJSON() ([]byte, error) {
	str := fmt.Sprintf("{\"%s\"}", p.name)
	return []byte(str), nil
}

func prfTranform(prfId uint16) (*Prf, error) {
	switch protocol.PrfTransformId(prfId) {
	case protocol.PRF_HMAC_SHA2_256:
		return &Prf{macPrf(sha256.New), sha256.Size, "sha256"}, nil
	case protocol.PRF_HMAC_SHA1:
		return &Prf{macPrf(sha1.New), sha1.Size, "sha1"}, nil
	default:
		return nil, fmt.Errorf("Unsupported PRF transfom: %s", prfId)
	}
}

type prfFunc func(key, data []byte) []byte

func macPrf(h func() hash.Hash) prfFunc {
	return func(key, data []byte) []byte {
		mac := hmac.New(h, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
}
