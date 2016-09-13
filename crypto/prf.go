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
	protocol.PrfTransformId
}

func (p *Prf) String() string {
	return p.PrfTransformId.String()
}

func prfTranform(prfId uint16) (*Prf, error) {
	switch prf := protocol.PrfTransformId(prfId); prf {
	case protocol.PRF_HMAC_SHA2_256:
		return &Prf{macPrf(sha256.New), sha256.Size, prf}, nil
	case protocol.PRF_HMAC_SHA1:
		return &Prf{macPrf(sha1.New), sha1.Size, prf}, nil
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
