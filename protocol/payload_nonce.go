package protocol

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

func (s *NoncePayload) Type() PayloadType {
	return PayloadTypeNonce
}

func (s *NoncePayload) Encode() (b []byte) {
	return s.Nonce.Bytes()
}

func (s *NoncePayload) Decode(b []byte) error {
	// Header has already been decoded
	// between 16 and 256 octets
	if len(b) < (16+PAYLOAD_HEADER_LENGTH) || len(b) > (256+PAYLOAD_HEADER_LENGTH) {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("NONCE length invalid: %d", len(b)))
	}
	s.Nonce = new(big.Int).SetBytes(b)
	return nil
}
