package ike

import (
	"bytes"
	"time"

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
	prop := protocol.ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, espSpi)
	return makeChildSa(
		&childSaParams{
			authParams: &authParams{
				isResponse:      !isInitiator,
				isInitiator:     isInitiator,
				isTransportMode: sess.cfg.IsTransportMode,
				spiI:            sess.IkeSpiI,
				spiR:            sess.IkeSpiR,
				proposals:       prop,
				tsI:             sess.cfg.TsI,
				tsR:             sess.cfg.TsR,
				lifetime:        sess.cfg.Lifetime,
			},
			targetEspSpi:  targetEspSpi,
			nonce:         no,
			dhTransformId: newTkm.suite.DhGroup.TransformId(),
			dhPublic:      newTkm.DhPublic,
		})
}

func handleChildSaResponse(sess *Session, newTkm *Tkm, params *childSaParams) (spi protocol.Spi, lt time.Duration, err error) {
	if params.targetEspSpi != nil {
		err = errors.Errorf("REKEY child SA response: target ESP unexpected")
		return
	}
	spi, lt, err = checkSaForSession(sess, params.authParams)
	if err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
		return
	}
	if params.dhPublic != nil {
		if err = newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return
		}
	}
	newTkm.Nr = params.nonce
	return
}

func handleChildSaRequest(sess *Session, newTkm *Tkm, params *childSaParams) (spi protocol.Spi, lt time.Duration, err error) {
	if params.targetEspSpi == nil {
		err = errors.Errorf("REKEY child SA request: missing target ESP")
		return
	}
	if !bytes.Equal(params.targetEspSpi, sess.EspSpiI) {
		err = errors.Errorf("REKEY child SA request: incorrect target ESP Spi: 0x%x, rx 0x%x",
			params.targetEspSpi, sess.EspSpiI)
		return
	}
	spi, lt, err = checkSaForSession(sess, params.authParams)
	if err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
		return
	}
	if params.dhPublic != nil {
		if err = newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return
		}
	}
	newTkm.Ni = params.nonce
	return
}
