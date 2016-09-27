package ike

import "github.com/msgboxio/ike/protocol"

type InfoParams struct {
	IsInitiator bool
	SpiI, SpiR  protocol.Spi
	Payload     protocol.Payload
}

// INFORMATIONAL
// b<-a
//  HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: none, Message ID=m),
//  SK {...}
// a<-b
// 	HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: Initiator | Response, Message ID=m),
//  SK {}
func MakeInformational(p InfoParams) *Message {
	flags := protocol.RESPONSE
	if p.IsInitiator {
		flags = protocol.INITIATOR
	}
	info := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         p.SpiI,
			SpiR:         p.SpiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.INFORMATIONAL,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	if p.Payload != nil {
		info.Payloads.Add(p.Payload)
	}
	return info
}
