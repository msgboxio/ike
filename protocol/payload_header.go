package protocol

import (
	"encoding/hex"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (h *PayloadHeader) NextPayloadType() PayloadType {
	return h.NextPayload
}

func (h *PayloadHeader) Header() *PayloadHeader {
	return h
}

func (h PayloadHeader) Encode(log log.Logger) (b []byte) {
	b = make([]byte, PAYLOAD_HEADER_LENGTH)
	packets.WriteB8(b, 0, uint8(h.NextPayload))
	packets.WriteB16(b, 2, h.PayloadLength+PAYLOAD_HEADER_LENGTH)
	level.Debug(log).Log("PayloadHeader", h, "to", hex.Dump(b))
	return
}

func (h *PayloadHeader) Decode(b []byte, log log.Logger) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Packet Too short : %d", len(b)))
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	level.Debug(log).Log("PayloadHeader", *h, "from", hex.Dump(b))
	return nil
}
