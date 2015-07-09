package ike

import (
	"bytes"
	"math/big"
)

type initParams struct {
	isInitiator bool
	spiI, spiR  Spi
	proposals   []*SaProposal

	nonce         *big.Int
	dhTransformId DhTransformId
	dhPublic      *big.Int
}

// IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]
func makeInit(p initParams) *Message {
	flags := RESPONSE
	// nonce := tkm.Nr
	if p.isInitiator {
		flags = INITIATOR
		// nonce = tkm.Ni
	}
	init := &Message{
		IkeHeader: &IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
			NextPayload:  PayloadTypeSA,
			MajorVersion: IKEV2_MAJOR_VERSION,
			MinorVersion: IKEV2_MINOR_VERSION,
			ExchangeType: IKE_SA_INIT,
			Flags:        flags,
		},
		Payloads: MakePayloads(),
	}
	init.Payloads.Add(&SaPayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeKE},
		Proposals:     p.proposals,
	})
	init.Payloads.Add(&KePayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNonce},
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	init.Payloads.Add(&NoncePayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNone},
		Nonce:         p.nonce,
	})
	return init
}

type authParams struct {
	isInitiator bool
	spiI, spiR  Spi
	proposals   []*SaProposal

	tsI, tsR []*Selector
}

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
func makeAuth(spiI, spiR Spi, proposals []*SaProposal, tsI, tsR []*Selector, signed1 []byte, tkm *Tkm) *Message {
	flags := RESPONSE
	idPayloadType := PayloadTypeIDr
	if tkm.isInitiator {
		flags = INITIATOR
		idPayloadType = PayloadTypeIDi
	}
	auth := &Message{
		IkeHeader: &IkeHeader{
			SpiI:         spiI,
			SpiR:         spiR,
			NextPayload:  PayloadTypeSK,
			MajorVersion: IKEV2_MAJOR_VERSION,
			MinorVersion: IKEV2_MINOR_VERSION,
			ExchangeType: IKE_AUTH,
			Flags:        flags,
		},
		Payloads: MakePayloads(),
	}
	id := &IdPayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeAUTH},
		idPayloadType: idPayloadType,
		IdType:        ID_RFC822_ADDR,
		Data:          tkm.AuthId(ID_RFC822_ADDR),
	}
	auth.Payloads.Add(id)
	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	auth.Payloads.Add(&AuthPayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeSA},
		AuthMethod:    SHARED_KEY_MESSAGE_INTEGRITY_CODE,
		Data:          tkm.Auth(signed1, id, SHARED_KEY_MESSAGE_INTEGRITY_CODE, flags),
	})
	auth.Payloads.Add(&SaPayload{
		PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeTSi},
		Proposals:     proposals,
	})
	auth.Payloads.Add(&TrafficSelectorPayload{
		PayloadHeader:              &PayloadHeader{NextPayload: PayloadTypeTSr},
		trafficSelectorPayloadType: PayloadTypeTSi,
		Selectors:                  tsI,
	})
	next := PayloadTypeNone
	if tkm.isInitiator {
		next = PayloadTypeN
	}
	auth.Payloads.Add(&TrafficSelectorPayload{
		PayloadHeader:              &PayloadHeader{NextPayload: next},
		trafficSelectorPayloadType: PayloadTypeTSr,
		Selectors:                  tsR,
	})
	// check for transport mode config
	if bytes.Equal(tsI[0].StartAddress, tsI[0].EndAddress) {
		auth.Payloads.Add(&NotifyPayload{
			PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeN},
			// ProtocolId:       IKE,
			NotificationType: USE_TRANSPORT_MODE,
		})
	}
	if tkm.isInitiator {
		auth.Payloads.Add(&NotifyPayload{
			PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNone},
			// ProtocolId:       IKE,
			NotificationType: INITIAL_CONTACT,
		})
	}
	return auth
}

type infoParams struct {
	isInitiator bool
	spiI, spiR  Spi
	payload     Payload
}

// INFORMATIONAL
func makeInformational(p infoParams) *Message {
	flags := RESPONSE
	if p.isInitiator {
		flags = INITIATOR
	}
	info := &Message{
		IkeHeader: &IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
			NextPayload:  PayloadTypeSK,
			MajorVersion: IKEV2_MAJOR_VERSION,
			MinorVersion: IKEV2_MINOR_VERSION,
			ExchangeType: INFORMATIONAL,
			Flags:        flags,
		},
		Payloads: MakePayloads(),
	}
	if p.payload != nil {
		info.Payloads.Add(p.payload)
	}
	return info
}
