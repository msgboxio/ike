package ike

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"

	"msgbox.io/ike/protocol"
	"msgbox.io/log"
)

var (
	InitPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeKE,
		protocol.PayloadTypeNonce,
	}

	AuthIPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDi,
		protocol.PayloadTypeAUTH,
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
	AuthRPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDr,
		protocol.PayloadTypeAUTH,
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
)

type Message struct {
	IkeHeader *protocol.IkeHeader
	Payloads  *protocol.Payloads
	Data      []byte // used to carry raw bytes
}

func (s *Message) DecodeHeader(b []byte) (err error) {
	s.IkeHeader, err = protocol.DecodeIkeHeader(b[:protocol.IKE_HEADER_LEN])
	return
}

func (s *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType) (err error) {
	if s.Payloads, err = protocol.DecodePayloads(b, nextPayload); err != nil {
		return
	}
	log.V(1).Infof("Received %s: payloads %s", s.IkeHeader.ExchangeType, *s.Payloads)
	if log.V(protocol.LOG_PACKET_JS) {
		js, _ := json.MarshalIndent(s, " ", " ")
		log.Info("Rx:\n" + string(js))
	}
	return
}

func (s *Message) Encode(tkm *Tkm) (b []byte, err error) {
	log.V(1).Infof("Sending %s: payloads %s", s.IkeHeader.ExchangeType, s.Payloads)
	if log.V(protocol.LOG_PACKET_JS) {
		js, _ := json.MarshalIndent(s, " ", " ")
		log.Info("Tx:\n" + string(js))
	}
	nextPayload := s.IkeHeader.NextPayload
	if nextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant encrypt, no tkm found")
			return
		}
		b, err = tkm.EncryptMac(s)
	} else {
		b = protocol.EncodePayloads(s.Payloads)
		s.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(s.IkeHeader.Encode(), b...)
	}
	return
}

func (msg *Message) EnsurePayloads(payloadTypes []protocol.PayloadType) bool {
	mp := msg.Payloads
	for _, pt := range payloadTypes {
		if mp.Get(pt) == nil {
			return false
		}
	}
	return true
}

type initParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi
	proposals   []*protocol.SaProposal

	nonce         *big.Int
	dhTransformId protocol.DhTransformId
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
	flags := protocol.RESPONSE
	// nonce := tkm.Nr
	if p.isInitiator {
		flags = protocol.INITIATOR
		// nonce = tkm.Ni
	}
	init := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
			NextPayload:  protocol.PayloadTypeSA,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	init.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeKE},
		Proposals:     p.proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeNonce},
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeNone},
		Nonce:         p.nonce,
	})
	return init
}

type authParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi
	proposals   []*protocol.SaProposal

	tsI, tsR []*protocol.Selector
}

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
func makeAuth(spiI, spiR protocol.Spi, proposals []*protocol.SaProposal, tsI, tsR []*protocol.Selector, signed1 []byte, tkm *Tkm) *Message {
	flags := protocol.RESPONSE
	idPayloadType := protocol.PayloadTypeIDr
	if tkm.isInitiator {
		flags = protocol.INITIATOR
		idPayloadType = protocol.PayloadTypeIDi
	}
	auth := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         spiI,
			SpiR:         spiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_AUTH,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	id := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeAUTH},
		IdPayloadType: idPayloadType,
		IdType:        protocol.ID_RFC822_ADDR,
		Data:          tkm.AuthId(protocol.ID_RFC822_ADDR),
	}
	auth.Payloads.Add(id)
	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeSA},
		AuthMethod:    protocol.SHARED_KEY_MESSAGE_INTEGRITY_CODE,
		Data:          tkm.Auth(signed1, id, protocol.SHARED_KEY_MESSAGE_INTEGRITY_CODE, flags),
	})
	auth.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeTSi},
		Proposals:     proposals,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeTSr},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
		Selectors:                  tsI,
	})
	next := protocol.PayloadTypeNone
	if tkm.isInitiator {
		next = protocol.PayloadTypeN
	}
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{NextPayload: next},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
		Selectors:                  tsR,
	})
	// check for transport mode config
	if bytes.Equal(tsI[0].StartAddress, tsI[0].EndAddress) {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeN},
			// ProtocolId:       IKE,
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if tkm.isInitiator {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeNone},
			// ProtocolId:       IKE,
			NotificationType: protocol.INITIAL_CONTACT,
		})
	}
	return auth
}

type infoParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi
	payload     protocol.Payload
}

// INFORMATIONAL
// b<-a
//  HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: none, Message ID=m),
//  SK {...}
// a<-b
// 	HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: Initiator | Response, Message ID=m),
//  SK {}
func makeInformational(p infoParams) *Message {
	flags := protocol.RESPONSE
	if p.isInitiator {
		flags = protocol.INITIATOR
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

	nonce         *big.Int
	dhTransformId protocol.DhTransformId
	dhPublic      *big.Int
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
	child.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeKE},
		Proposals:     p.proposals,
	})
	child.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeNonce},
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	child.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{NextPayload: protocol.PayloadTypeNone},
		Nonce:         p.nonce,
	})
	return child

}
