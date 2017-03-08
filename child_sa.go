package ike

import (
	"bytes"
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
	targetEspSpi     protocol.Spi // esp sa that is being replaced
	nonce            *big.Int
	dhTransformId    protocol.DhTransformId
	dhPublic         *big.Int
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
			Spi:              params.targetEspSpi, // target esp
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
	if params.dhPublic != nil { // optional
		child.Payloads.Add(&protocol.KePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			DhTransformId: params.dhTransformId,
			KeyData:       params.dhPublic,
		})
	}
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

// HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}   -->
// <--  HDR, SK {SA, Nr, [KEr,] TSi, TSr}
// ChildSaFromSession creates CREATE_CHILD_SA messages
func ChildSaFromSession(o *Session, newTkm *Tkm, isInitiator bool, espSpi []byte) *Message {
	no := newTkm.Nr
	targetEspSpi := o.EspSpiR
	if isInitiator {
		no = newTkm.Ni
		targetEspSpi = o.EspSpiI
	}
	prop := ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, espSpi)
	return makeChildSa(&childSaParams{
		isResponse:    !isInitiator,
		isInitiator:   isInitiator,
		ikeSpiI:       o.IkeSpiI,
		ikeSpiR:       o.IkeSpiR,
		proposals:     prop,
		tsI:           o.cfg.TsI,
		tsR:           o.cfg.TsR,
		lifetime:      o.cfg.Lifetime,
		targetEspSpi:  targetEspSpi,
		nonce:         no,
		dhTransformId: newTkm.suite.DhGroup.TransformId(),
		dhPublic:      newTkm.DhPublic,
	})
}

func parseChildSa(m *Message) (*childSaParams, error) {
	if m.IkeHeader.ExchangeType != protocol.CREATE_CHILD_SA {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "CREATE_CHILD_SA: incorrect type")
	}
	params := &childSaParams{}
	if m.IkeHeader.Flags&protocol.RESPONSE != 0 {
		params.isResponse = true
	}
	if m.IkeHeader.Flags&protocol.INITIATOR != 0 {
		params.isInitiator = true
	}
	rekeySA := m.Payloads.GetNotification(protocol.REKEY_SA)
	if rekeySA != nil {
		// received CREATE_CHILD_SA request
		// make sure protocol id is correct
		if rekeySA.ProtocolId != protocol.ESP {
			return nil, errors.New("REKEY child SA: Wrong protocol")
		}
		params.targetEspSpi = rekeySA.Spi
	}
	if err := m.EnsurePayloads(RekeyChildSaPaylods); err == nil {
		// rekeying IPSEC SA
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		tsI := m.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
		tsR := m.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
		if len(tsI) == 0 || len(tsR) == 0 {
			return nil,
				errors.New("REKEY child SA: acceptable traffic selectors are missing")
		}
		params.tsI = tsI
		params.tsR = tsR
		// check for optional KE payload
		if kep := m.Payloads.Get(protocol.PayloadTypeKE); kep != nil {
			keR := kep.(*protocol.KePayload)
			params.dhPublic = keR.KeyData
			params.dhTransformId = keR.DhTransformId
		}
	} else if err := m.EnsurePayloads(RekeyIkeSaPaylods); err == nil {
		// rekeying IKE SA
		// get sa & nonce
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
		params.dhPublic = keR.KeyData
		params.dhTransformId = keR.DhTransformId
	} else {
		return nil, errors.New("REKEY packet is invalid")
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

// HandleChildSaForSession currently suppports CREATE_CHILD_SA messages for creating child sa
func HandleChildSaForSession(o *Session, newTkm *Tkm, asInitiator bool, params *childSaParams) (protocol.Spi, error) {
	// check spi if CREATE_CHILD_SA request received as responder
	if !asInitiator {
		if !bytes.Equal(params.targetEspSpi, o.EspSpiI) {
			return nil, errors.Errorf("REKEY child SA request: incorrect target ESP Spi: 0x%x, rx 0x%x",
				params.targetEspSpi, o.EspSpiI)
		}
	}
	if params.dhPublic == nil {
		// return nil, errors.New("REKEY child SA: missing DH parameters")
	} else {
		if err := newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return nil, err
		}
	}
	// proposal should be identical
	if err := o.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		return nil, err
	}
	// set Nr
	if asInitiator {
		newTkm.Nr = params.nonce
	} else {
		newTkm.Ni = params.nonce
	}
	// get new esp from proposal
	return spiFromProposal(params.proposals, protocol.ESP)
}
