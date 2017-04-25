package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
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

func prfTranform(prfID uint16) (*Prf, error) {
	switch prf := protocol.PrfTransformId(prfID); prf {
	case protocol.PRF_HMAC_SHA2_256:
		return &Prf{macPrf(sha256.New), sha256.Size, prf}, nil
	case protocol.PRF_HMAC_SHA2_384:
		return &Prf{macPrf(sha512.New384), sha512.Size384, prf}, nil
	case protocol.PRF_HMAC_SHA1:
		return &Prf{macPrf(sha1.New), sha1.Size, prf}, nil
	default:
		return nil, errors.Errorf("Unsupported PRF transfom: %s", prf)
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
