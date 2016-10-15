package protocol

import (
	"fmt"
	"math/big"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (s *KePayload) Type() PayloadType { return PayloadTypeKE }

func (s *KePayload) Encode() (b []byte) {
	b = make([]byte, 4)
	packets.WriteB16(b, 0, uint16(s.DhTransformId))
	return append(b, s.KeyData.Bytes()...)
}

func (s *KePayload) Decode(b []byte) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("KE too small %d < %d", len(b), 4))
	}
	// Header has already been decoded
	gn, _ := packets.ReadB16(b, 0)
	s.DhTransformId = DhTransformId(gn)
	s.KeyData = new(big.Int).SetBytes(b[4:])
	return nil
}
