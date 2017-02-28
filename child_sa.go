package ike

import (
	"math/big"
	"time"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// CREATE_CHILD_SA
// b<-a
//  HDR(SPIi=xxx, SPIy=yyy, CREATE_CHILD_SA, Flags: none, Message ID=m),
//  SK {SA, Ni, KEi} - ike sa
//  SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr} - for rekey child sa
//  SK {SA, Ni, [KEi,] TSi, TSr} - for new child sa, different selector perhaps
// a<-b
//  HDR(SPIi=xxx, SPIr=yyy, CREATE_CHILD_SA, Flags: Initiator | Response, Message ID=m),
//  SK {N(NO_ADDITIONAL_SAS} - reject
//  SK {SA, Nr, KEr} - ike sa
//  SK {SA, Nr, [KEr,] TSi, TSr} - child sa
type childSaParams struct {
	isResponse       bool
	isInitiator      bool
	isTransportMode  bool
	ikeSpiI, ikeSpiR protocol.Spi
	proposals        []*protocol.SaProposal
	tsI, tsR         []*protocol.Selector
	lifetime         time.Duration

	espSpi        protocol.Spi
	nonce         *big.Int
	dhTransformId protocol.DhTransformId
	dhPublic      *big.Int
}

func makeChildSa(params *childSaParams) *Message {
	flags := protocol.IkeFlags(0)
	if params.isResponse {
		flags = protocol.RESPONSE
	}
	if params.isInitiator {
		flags |= protocol.INITIATOR
	}
	child := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         params.ikeSpiI,
			SpiR:         params.ikeSpiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.CREATE_CHILD_SA,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	// presence of traffic selectors means that CHILD SA is being rekeyed
	if params.tsI != nil && params.tsR != nil && params.isInitiator {
		child.Payloads.Add(&protocol.NotifyPayload{
			ProtocolId:       protocol.ESP,
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.REKEY_SA,
			Spi:              params.espSpi, // our inbound spi
		})
	}
	child.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     params.proposals,
	})
	child.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         params.nonce,
	})
	child.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: params.dhTransformId,
		KeyData:       params.dhPublic,
	})
	if params.tsI != nil && params.tsR != nil {
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
			Selectors:                  params.tsI,
		})
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
			Selectors:                  params.tsR,
		})
	}
	if params.isTransportMode {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if !params.isInitiator && params.lifetime != 0 {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType:    protocol.AUTH_LIFETIME,
			NotificationMessage: params.lifetime,
		})
	}
	return child
}

func parseChildSa(m *Message) (*childSaParams, error) {
	params := &childSaParams{}
	if m.IkeHeader.Flags&protocol.RESPONSE != 0 {
		params.isResponse = true
	}
	if m.IkeHeader.Flags&protocol.INITIATOR != 0 {
		params.isInitiator = true
	}
	// what kind of rekey request
	rekeySA := m.Payloads.GetNotification(protocol.REKEY_SA)
	if rekeySA == nil {
		// rekeying IKE SA
		if err := m.EnsurePayloads(RekeyIkeSaPaylods); err == nil {
			return nil, err
		}
		// get sa & nonce
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
		params.dhPublic = keR.KeyData
		params.dhTransformId = keR.DhTransformId
	} else {
		// rekeying IPSEC SA
		if err := m.EnsurePayloads(RekeyChildSaPaylods); err == nil {
			return nil, err
		}
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		tsI := m.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
		tsR := m.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
		if len(tsI) == 0 || len(tsR) == 0 {
			return nil, errors.New("REKEY child SA request: acceptable traffic selectors are missing")
		}
		params.tsI = tsI
		params.tsR = tsR
		params.espSpi = rekeySA.Spi
		if kep := m.Payloads.Get(protocol.PayloadTypeKE); kep != nil { // optional
			keR := kep.(*protocol.KePayload)
			params.dhPublic = keR.KeyData
			params.dhTransformId = keR.DhTransformId
		}
	}
	// notifications
	wantsTransportMode := false
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.AUTH_LIFETIME:
			params.lifetime = ns.NotificationMessage.(time.Duration)
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	params.isTransportMode = wantsTransportMode
	return params, nil
}
