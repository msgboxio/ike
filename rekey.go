package ike

import (
	"bytes"
	"errors"

	"github.com/msgboxio/ike/protocol"
)

var ErrorRekeyDeadlineExceeded = errors.New("Rekey Deadline Exceeded")

// HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}   -->
// <--  HDR, SK {SA, Nr, [KEr,] TSi, TSr}

func (o *Session) SaRekey(newTkm *Tkm, isInitiator bool, espSpi []byte) (*OutgoingMessge, error) {
	no := newTkm.Nr
	targetEspSpi := o.EspSpiR
	if isInitiator {
		no = newTkm.Ni
		targetEspSpi = o.EspSpiI
	}
	prop := ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, espSpi)
	child := makeChildSa(&childSaParams{
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
	msgId := o.msgIdResp
	if o.isInitiator {
		msgId = o.msgIdReq
	}
	child.IkeHeader.MsgId = msgId
	// encode & send
	return o.encode(child)
}

func HandleSaRekey(o *Session, newTkm *Tkm, asInitiator bool, msg interface{}) (protocol.Spi, error) {
	m := msg.(*Message)
	params, err := parseChildSa(m)
	if err != nil {
		return nil, err
	}
	// check spi if CREATE_CHILD_SA request received as responder
	if !asInitiator {
		spi := o.EspSpiR
		if !bytes.Equal(params.targetEspSpi, spi) {
			return nil, errors.New("REKEY child SA request: incorrect target ESP Spi")
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
	if err = o.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
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

/*
	// get new IKE spi
	peerSpi, err := getPeerSpi(m, protocol.IKE)
	if err != nil {
		o.Logger.Error(err)
		return nil
	}
	o.IkeSpiR = append([]byte{}, peerSpi...)
	// create rest of ike sa
	newTkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, o.tkm.skD)
	o.Logger.Infof("NEW IKE SA Established: %#x<=>%#x",
		o.IkeSpiI,
		o.IkeSpiR)
	// save Data
	o.initRb = m.Data
*/
