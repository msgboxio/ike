package protocol

import (
	"encoding/hex"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (h *PayloadHeader) NextPayloadType() PayloadType {
	return h.NextPayload
}

func (h *PayloadHeader) Header() *PayloadHeader {
	return h
}

func (h PayloadHeader) Encode(log *logrus.Logger) (b []byte) {
	b = make([]byte, PAYLOAD_HEADER_LENGTH)
	packets.WriteB8(b, 0, uint8(h.NextPayload))
	packets.WriteB16(b, 2, h.PayloadLength+PAYLOAD_HEADER_LENGTH)
	log.Debugf("Payload Header: %+v to \n%s", h, hex.Dump(b))
	return
}

func (h *PayloadHeader) Decode(b []byte, log *logrus.Logger) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Packet Too short : %d", len(b)))
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	log.Debugf("Payload Header: %+v from \n%s", *h, hex.Dump(b))
	return nil
}
