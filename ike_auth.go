package ike

import "github.com/msgboxio/ike/protocol"

type authParams struct {
	isInitiator     bool
	isTransportMode bool
	spiI, spiR      protocol.Spi
	proposals       []*protocol.SaProposal
	tsI, tsR        []*protocol.Selector
	Identities
	Authenticator
}

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
// signed1 : init[i/r]B | N[r/i]
func makeAuth(params *authParams, initB []byte) *Message {
	// spiI, spiR protocol.Spi, proposals []*protocol.SaProposal, tsI, tsR []*protocol.Selector, signed1 []byte, tkm *Tkm, isTransportMode bool) *Message {
	flags := protocol.RESPONSE
	idPayloadType := protocol.PayloadTypeIDr
	if params.isInitiator {
		flags = protocol.INITIATOR
		idPayloadType = protocol.PayloadTypeIDi
	}
	auth := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         params.spiI,
			SpiR:         params.spiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_AUTH,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	// TODO - handle various other types of ID
	iD := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		IdPayloadType: idPayloadType,
		IdType:        params.Identities.IdType(),
		Data:          params.Identities.Id(),
	}
	auth.Payloads.Add(iD)
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    params.Authenticator.AuthMethod(),
		Data:          params.Authenticator.Sign(initB, iD, params.Identities),
	})
	auth.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     params.proposals,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
		Selectors:                  params.tsI,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
		Selectors:                  params.tsR,
	})
	// check for transport mode config
	if params.isTransportMode {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if params.isInitiator {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.INITIAL_CONTACT,
		})
	}
	return auth
}
