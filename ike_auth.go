package ike

import (
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

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
// signed1 : init[i/r]B | N[r/i]
func makeAuth(spiI, spiR protocol.Spi, proposals []*protocol.SaProposal, tsI, tsR []*protocol.Selector, signed1 []byte, tkm *Tkm, isTransportMode bool) *Message {
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
	// TODO - handle various other types of ID
	authenticator := &psk{tkm}
	iD := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		IdPayloadType: idPayloadType,
		IdType:        authenticator.IdType(),
		Data:          authenticator.Id(),
	}
	auth.Payloads.Add(iD)
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    authenticator.AuthMethod(),
		Data:          authenticator.Sign(signed1, iD, flags),
	})
	auth.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     proposals,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
		Selectors:                  tsI,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
		Selectors:                  tsR,
	})
	// check for transport mode config
	if isTransportMode {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if tkm.isInitiator {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.INITIAL_CONTACT,
		})
	}
	return auth
}

func AuthMsg(
	tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	initIb, initRb []byte,
	msgID uint32,
	cfg *Config,
	local, remote net.IP) ([]byte, error) {
	// IKE_AUTH
	// make sure selectors are present
	if cfg.TsI == nil || cfg.TsR == nil {
		log.Infoln("Adding host based selectors")
		// add host based selectors by default
		slen := len(local) * 8
		ini := remote
		res := local
		if tkm.isInitiator {
			ini = local
			res = remote
		}
		cfg.AddSelector(
			&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
			&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
	}
	log.Infof("SA selectors: [INI]%s<=>%s[RES]", cfg.TsI, cfg.TsR)

	// proposal
	var prop []*protocol.SaProposal
	// part of signed octet
	var signed1 []byte
	if tkm.isInitiator {
		prop = ProposalFromTransform(protocol.ESP, cfg.ProposalEsp, espSpiI)
		// intiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		signed1 = append(initIb, tkm.Nr.Bytes()...)
	} else {
		prop = ProposalFromTransform(protocol.ESP, cfg.ProposalEsp, espSpiR)
		// responder's signed octet
		// initR | Ni | prf(sk_pr | IDr )
		signed1 = append(initRb, tkm.Ni.Bytes()...)
	}
	auth := makeAuth(ikeSpiI, ikeSpiR, prop, cfg.TsI, cfg.TsR, signed1, tkm, cfg.IsTransportMode)
	auth.IkeHeader.MsgId = msgID
	// encode
	return auth.Encode(tkm)
}
