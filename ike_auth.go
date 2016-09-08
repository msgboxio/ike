package ike

import (
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

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
