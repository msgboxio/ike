package ike

import "github.com/msgboxio/ike/protocol"

type InfoParams struct {
	IsInitiator bool
	IsResponse  bool
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
// Notification, Delete, and Configuration Payloads
// Must be replied to
func MakeInformational(p InfoParams) *Message {
	var flags protocol.IkeFlags
	if p.IsResponse {
		flags |= protocol.RESPONSE
	}
	if p.IsInitiator {
		flags |= protocol.INITIATOR
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

func NotifyFromSession(o *Session, ie protocol.IkeErrorCode) *Message {
	spi := o.IkeSpiI
	if o.isInitiator {
		spi = o.IkeSpiR
	}
	// always a request
	return MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
		Payload: &protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			ProtocolId:       protocol.IKE,
			NotificationType: protocol.NotificationType(ie),
			Spi:              spi,
		},
	})
}

func DeleteFromSession(o *Session) *Message {
	// ike protocol ID, but no spi
	// always a request
	return MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
		Payload: &protocol.DeletePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			ProtocolId:    protocol.IKE,
			Spis:          []protocol.Spi{},
		},
	})
}

func EmptyFromSession(o *Session, isResponse bool) *Message {
	return MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		IsResponse:  isResponse,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
	})
}
