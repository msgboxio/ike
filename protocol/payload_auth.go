package protocol

import (
	"fmt"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (s *AuthPayload) Type() PayloadType {
	return PayloadTypeAUTH
}

func (s *AuthPayload) Encode() (b []byte) {
	b = []byte{uint8(s.AuthMethod), 0, 0, 0}
	return append(b, s.Data...)
}

func (s *AuthPayload) Decode(b []byte) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("auth too small %d < %d", len(b), 4))
	}
	// Header has already been decoded
	authMethod, _ := packets.ReadB8(b, 0)
	s.AuthMethod = AuthMethod(authMethod)
	s.Data = append([]byte{}, b[4:]...)
	return nil
}

func (s *SignatureAuth) Encode() (b []byte) {
	b = append([]byte{byte(len(s.Asn1Data))}, s.Asn1Data...)
	return append(b, s.Signature...)
}

func (s *SignatureAuth) Decode(b []byte) error {
	if len(b) < 1 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("signature auth too small %d < %d", len(b), 1))
	}
	asnLen, _ := packets.ReadB8(b, 0)
	s.Asn1Data = append([]byte{}, b[1:1+asnLen]...)
	s.Signature = append([]byte{}, b[asnLen+1:]...)
	return nil
}
