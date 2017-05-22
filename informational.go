package ike

import (
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

type infoParams struct {
	isInitiator bool
	isResponse  bool
	spiI, spiR  protocol.Spi
	payload     protocol.Payload
}

type SessionNotificationType int

const (
	MSG_EMPTY_REQUEST SessionNotificationType = iota
	MSG_EMPTY_RESPONSE
	MSG_NOTIFICATION
	MSG_ERROR
)

type InformationalEvent struct {
	SessionNotificationType
	Message interface{}
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
func makeInformational(p infoParams) *Message {
	var flags protocol.IkeFlags
	if p.isResponse {
		flags |= protocol.RESPONSE
	}
	if p.isInitiator {
		flags |= protocol.INITIATOR
	}
	info := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.INFORMATIONAL,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	if p.payload != nil {
		info.Payloads.Add(p.payload)
	}
	return info
}

// NotifyFromSession builds a Notification Request
func NotifyFromSession(sess *Session, ie protocol.IkeErrorCode, isResponse bool) *Message {
	spi := sess.IkeSpiI
	if sess.isInitiator {
		spi = sess.IkeSpiR
	}
	return makeInformational(infoParams{
		isInitiator: sess.isInitiator,
		isResponse:  isResponse,
		spiI:        sess.IkeSpiI,
		spiR:        sess.IkeSpiR,
		payload: &protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			ProtocolId:       protocol.IKE,
			NotificationType: protocol.NotificationType(ie),
			Spi:              spi,
		},
	})
}

// DeleteFromSession builds an IKE delete Request
func DeleteFromSession(sess *Session) *Message {
	// ike protocol ID, but no spi
	// always a request
	return makeInformational(infoParams{
		isInitiator: sess.isInitiator,
		spiI:        sess.IkeSpiI,
		spiR:        sess.IkeSpiR,
		payload: &protocol.DeletePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			ProtocolId:    protocol.IKE,
			Spis:          []protocol.Spi{},
		},
	})
}

// EmptyFromSession can build an empty Request or a Response
func EmptyFromSession(sess *Session, isResponse bool) *Message {
	return makeInformational(infoParams{
		isInitiator: sess.isInitiator,
		isResponse:  isResponse,
		spiI:        sess.IkeSpiI,
		spiR:        sess.IkeSpiR,
	})
}

// HandleInformationalForSession handles informational from peer
// TODO : handles a single payload only
func HandleInformationalForSession(sess *Session, msg *Message) *InformationalEvent {
	plds := msg.Payloads
	// Empty
	if len(plds.Array) == 0 {
		evt := MSG_EMPTY_REQUEST
		if msg.IkeHeader.Flags.IsResponse() {
			evt = MSG_EMPTY_RESPONSE
		}
		return &InformationalEvent{
			SessionNotificationType: evt,
		}
	}
	// Delete
	if del := plds.Get(protocol.PayloadTypeD); del != nil {
		dp := del.(*protocol.DeletePayload)
		if dp.ProtocolId == protocol.IKE {
			return &InformationalEvent{
				SessionNotificationType: MSG_ERROR,
				Message:                 errors.Wrapf(errPeerRemovedIkeSa, "NOTIFICATION: SA %s", msg.IkeHeader.SpiI),
			}
		}
		for _, spi := range dp.Spis {
			if dp.ProtocolId == protocol.ESP {
				return &InformationalEvent{
					SessionNotificationType: MSG_ERROR,
					Message:                 errors.Wrapf(errPeerRemovedEspSa, "NOTIFICATION: SA %s", spi),
				}
			}
		}
	}
	// Notification
	// delete the ike sa if notification is one of following
	// UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, AUTHENTICATION_FAILED
	if note := plds.Get(protocol.PayloadTypeN); note != nil {
		np := note.(*protocol.NotifyPayload)
		if err, ok := protocol.GetIkeErrorCode(np.NotificationType); ok {
			return &InformationalEvent{
				SessionNotificationType: MSG_ERROR,
				Message:                 err,
			}
		}
		level.Warn(sess.Logger).Log("INFORMATIONAL", "unhandled", "NOTIFICATION", np)
	}
	// Configuration
	if cfg := plds.Get(protocol.PayloadTypeCP); cfg != nil {
		cp := cfg.(*protocol.ConfigurationPayload)
		return &InformationalEvent{
			SessionNotificationType: MSG_NOTIFICATION,
			Message:                 cp,
		}
	}
	level.Warn(sess.Logger).Log("INFORMATIONAL", "unhandled", "PAYLOADS", plds)
	return nil
}
