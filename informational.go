package ike

import (
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

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
func makeInformational(p InfoParams) *Message {
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

// NotifyFromSession builds a Notification Request
func NotifyFromSession(o *Session, ie protocol.IkeErrorCode) *Message {
	spi := o.IkeSpiI
	if o.isInitiator {
		spi = o.IkeSpiR
	}
	return makeInformational(InfoParams{
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

// DeleteFromSession builds an IKE delete Request
func DeleteFromSession(o *Session) *Message {
	// ike protocol ID, but no spi
	// always a request
	return makeInformational(InfoParams{
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

// EmptyFromSession can build an empty Request or a Response
func EmptyFromSession(o *Session, isResponse bool) *Message {
	return makeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		IsResponse:  isResponse,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
	})
}

func HandleInformationalForSession(o *Session, msg *Message) *state.StateEvent {
	plds := msg.Payloads
	// Empty
	if len(plds.Array) == 0 {
		evt := state.MSG_EMPTY_REQUEST
		if msg.IkeHeader.Flags.IsResponse() {
			evt = state.MSG_EMPTY_RESPONSE
		}
		return &state.StateEvent{
			Event: evt,
		}
	}
	// Delete
	if del := plds.Get(protocol.PayloadTypeD); del != nil {
		dp := del.(*protocol.DeletePayload)
		if dp.ProtocolId == protocol.IKE {
			log.Infof(o.Tag()+"Peer remove IKE SA : %#x", msg.IkeHeader.SpiI)
			return &state.StateEvent{
				Event:   state.MSG_DELETE_IKE_SA,
				Message: msg.IkeHeader.SpiI,
			}
		}
		for _, spi := range dp.Spis {
			if dp.ProtocolId == protocol.ESP {
				log.Infof(o.Tag()+"Peer remove ESP SA : %#x", spi)
				return &state.StateEvent{
					Event:   state.MSG_DELETE_ESP_SA,
					Message: spi,
				}
			}
		}
	}
	// Notification
	// delete the ike sa if notification is one of following
	// UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, an AUTHENTICATION_FAILED
	if note := plds.Get(protocol.PayloadTypeN); note != nil {
		np := note.(*protocol.NotifyPayload)
		if err, ok := protocol.GetIkeErrorCode(np.NotificationType); ok {
			log.Infof(o.Tag()+"Received Informational Error: %v", err)
			return &state.StateEvent{
				Event:   state.FAIL,
				Error:   err,
				Message: msg,
			}
		}
	}
	// Configuration
	if cfg := plds.Get(protocol.PayloadTypeCP); cfg != nil {
		cp := cfg.(*protocol.ConfigurationPayload)
		log.V(1).Infof("Configuration: %+v", cp)
		// TODO
	}
	return nil
}
