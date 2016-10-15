package protocol

import (
	"fmt"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (s *CertPayload) Type() PayloadType {
	return PayloadTypeCERT
}

func (s *CertPayload) Encode() (b []byte) {
	b = []byte{uint8(s.CertEncodingType)}
	return append(b, s.Data...)
}

func (s *CertPayload) Decode(b []byte) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("id too small %d < %d", len(b), 4))
	}
	// Header has already been decoded
	ct, _ := packets.ReadB8(b, 0)
	s.CertEncodingType = CertEncodingType(ct)
	s.Data = append([]byte{}, b[1:]...)
	return nil
}
