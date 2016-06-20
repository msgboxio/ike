package protocol

import (
	"math/big"

	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

func (s *KePayload) Type() PayloadType { return PayloadTypeKE }

func (s *KePayload) Encode() (b []byte) {
	b = make([]byte, 4)
	packets.WriteB16(b, 0, uint16(s.DhTransformId))
	return append(b, s.KeyData.Bytes()...)
}

func (s *KePayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	// Header has already been decoded
	gn, _ := packets.ReadB16(b, 0)
	s.DhTransformId = DhTransformId(gn)
	s.KeyData = new(big.Int).SetBytes(b[4:])
	return
}
