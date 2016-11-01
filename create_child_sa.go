package ike

import (
	"math/big"

	"github.com/msgboxio/ike/protocol"
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
	isInitiator bool
	spiI, spiR  protocol.Spi

	proposals []*protocol.SaProposal

	nonce           *big.Int
	dhTransformId   protocol.DhTransformId
	dhPublic        *big.Int
	tsI, tsR        []*protocol.Selector
	isTransportMode bool
}

func makeIkeChildSa(p childSaParams) *Message {
	flags := protocol.RESPONSE
	// nonce := tkm.Nr
	if p.isInitiator {
		flags = protocol.INITIATOR
		// nonce = tkm.Ni
	}
	child := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.CREATE_CHILD_SA,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	if p.tsI != nil && p.tsR != nil {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.REKEY_SA,
		})
	}
	if p.isTransportMode {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	child.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     p.proposals,
	})
	child.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         p.nonce,
	})
	child.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	if p.tsI != nil && p.tsR != nil {
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
			Selectors:                  p.tsI,
		})
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
			Selectors:                  p.tsR,
		})
	}
	return child
}
