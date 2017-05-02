package ike

import (
	"bytes"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}   -->
// <--  HDR, SK {SA, Nr, [KEr,] TSi, TSr}
// ChildSaFromSession creates CREATE_CHILD_SA messages
func ChildSaFromSession(sess *Session, newTkm *Tkm, isInitiator bool, espSpi []byte) *Message {
	no := newTkm.Nr
	targetEspSpi := sess.EspSpiR
	if isInitiator {
		no = newTkm.Ni
		targetEspSpi = sess.EspSpiI
	}
	prop := ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, espSpi)
	return makeChildSa(&childSaParams{
		isResponse:    !isInitiator,
		isInitiator:   isInitiator,
		ikeSpiI:       sess.IkeSpiI,
		ikeSpiR:       sess.IkeSpiR,
		proposals:     prop,
		tsI:           sess.cfg.TsI,
		tsR:           sess.cfg.TsR,
		lifetime:      sess.cfg.Lifetime,
		targetEspSpi:  targetEspSpi,
		nonce:         no,
		dhTransformId: newTkm.suite.DhGroup.TransformId(),
		dhPublic:      newTkm.DhPublic,
	})
}

// HandleChildSaForSession currently suppports CREATE_CHILD_SA messages for creating child sa
func HandleChildSaForSession(sess *Session, newTkm *Tkm, asInitiator bool, params *childSaParams) (protocol.Spi, error) {
	// check spi if CREATE_CHILD_SA request received as responder
	if !asInitiator {
		if !bytes.Equal(params.targetEspSpi, sess.EspSpiI) {
			return nil, errors.Errorf("REKEY child SA request: incorrect target ESP Spi: 0x%x, rx 0x%x",
				params.targetEspSpi, sess.EspSpiI)
		}
	}
	if params.dhPublic == nil {
		// return nil, errors.New("REKEY child SA: missing DH parameters")
	} else {
		// MUTATION
		if err := newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return nil, err
		}
	}
	// proposal should be identical
	if err := sess.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		return nil, err
	}
	// set Nr
	// MUTATION
	if asInitiator {
		newTkm.Nr = params.nonce
	} else {
		newTkm.Ni = params.nonce
	}
	// get new esp from proposal
	return spiFromProposal(params.proposals, protocol.ESP)
}
