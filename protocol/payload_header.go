package protocol

import (
	"encoding/hex"

	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

func (h *PayloadHeader) NextPayloadType() PayloadType {
	return h.NextPayload
}

func (h *PayloadHeader) Header() *PayloadHeader {
	return h
}

func (h PayloadHeader) Encode() (b []byte) {
	b = make([]byte, PAYLOAD_HEADER_LENGTH)
	packets.WriteB8(b, 0, uint8(h.NextPayload))
	packets.WriteB16(b, 2, h.PayloadLength+PAYLOAD_HEADER_LENGTH)
	log.V(LOG_CODEC).Infof("Payload Header: %+v to \n%s", h, hex.Dump(b))
	return
}

func (h *PayloadHeader) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Infof("Packet Too short : %d", len(b))
		return ERR_INVALID_SYNTAX
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	log.V(LOG_CODEC).Infof("Payload Header: %+v from \n%s", *h, hex.Dump(b))
	return
}
