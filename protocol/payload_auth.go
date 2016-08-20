package protocol

import "github.com/msgboxio/packets"

func (s *AuthPayload) Type() PayloadType {
	return PayloadTypeAUTH
}

func (s *AuthPayload) Encode() (b []byte) {
	b = []byte{uint8(s.AuthMethod), 0, 0, 0}
	return append(b, s.Data...)
}

func (s *AuthPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		err = ErrF(ERR_INVALID_SYNTAX, "auth too small %d < %d", len(b), 4)
		return
	}
	// Header has already been decoded
	authMethod, _ := packets.ReadB8(b, 0)
	s.AuthMethod = AuthMethod(authMethod)
	s.Data = append([]byte{}, b[4:]...)
	return
}
