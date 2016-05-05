package protocol

import (
	"encoding/hex"

	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

func DecodeIkeHeader(b []byte) (h *IkeHeader, err error) {
	h = &IkeHeader{}
	if len(b) < IKE_HEADER_LEN {
		log.V(LOG_CODEC_ERR).Infof("Packet Too short : %d", len(b))
		return nil, ERR_INVALID_SYNTAX
	}
	h.SpiI = append([]byte{}, b[:8]...)
	h.SpiR = append([]byte{}, b[8:16]...)
	pt, _ := packets.ReadB8(b, 16)
	h.NextPayload = PayloadType(pt)
	ver, _ := packets.ReadB8(b, 16+1)
	h.MajorVersion = ver >> 4
	h.MinorVersion = ver & 0x0f
	et, _ := packets.ReadB8(b, 16+2)
	h.ExchangeType = IkeExchangeType(et)
	flags, _ := packets.ReadB8(b, 16+3)
	h.Flags = IkeFlags(flags)
	h.MsgId, _ = packets.ReadB32(b, 16+4)
	h.MsgLength, _ = packets.ReadB32(b, 16+8)
	if h.MsgLength < IKE_HEADER_LEN {
		log.V(LOG_CODEC_ERR).Infof("")
		return nil, ERR_INVALID_SYNTAX
	}
	log.V(LOG_CODEC).Infof("Ike Header: %+v from \n%s", *h, hex.Dump(b[:IKE_HEADER_LEN]))
	return
}

func (h *IkeHeader) Encode() (b []byte) {
	b = make([]byte, IKE_HEADER_LEN)
	copy(b, h.SpiI[:])
	copy(b[8:], h.SpiR[:])
	packets.WriteB8(b, 16, uint8(h.NextPayload))
	packets.WriteB8(b, 17, h.MajorVersion<<4|h.MinorVersion)
	packets.WriteB8(b, 18, uint8(h.ExchangeType))
	packets.WriteB8(b, 19, uint8(h.Flags))
	packets.WriteB32(b, 20, h.MsgId)
	packets.WriteB32(b, 24, h.MsgLength)
	log.V(LOG_CODEC).Infof("Ike Header: %+v to \n%s", *h, hex.Dump(b))
	return
}
