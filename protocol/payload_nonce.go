package protocol

import (
	"math/big"

	"github.com/msgboxio/log"
)

func (s *NoncePayload) Type() PayloadType {
	return PayloadTypeNonce
}

func (s *NoncePayload) Encode() (b []byte) {
	return s.Nonce.Bytes()
}

func (s *NoncePayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	// between 16 and 256 octets
	if len(b) < (16+PAYLOAD_HEADER_LENGTH) || len(b) > (256+PAYLOAD_HEADER_LENGTH) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	s.Nonce = new(big.Int).SetBytes(b)
	return
}
