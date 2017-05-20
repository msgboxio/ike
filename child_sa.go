package ike

import (
	"bytes"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// ChildSaFromSession creates CREATE_CHILD_SA messages
// HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}   -->
// <--  HDR, SK {SA, Nr, [KEr,] TSi, TSr}
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

func checkIpsecRekeyRequest(sess *Session, params *childSaParams) (espSpiI protocol.Spi, err error) {
	if params.tsI == nil || params.tsR == nil {
		err = errors.Errorf("CREATE_CHILD_SA request: selectors are missing. Rekeying IKE SA unsupported")
		return
	}
	if params.targetEspSpi == nil {
		err = errors.Errorf("CREATE_CHILD_SA request: missing target ESP")
		return
	}
	if !bytes.Equal(params.targetEspSpi, sess.EspSpiI) {
		err = errors.Errorf("CREATE_CHILD_SA request: incorrect target ESP Spi: 0x%x, rx 0x%x",
			params.targetEspSpi, sess.EspSpiI)
		return
	}
	espSpiI, _, err = checkSelectorsForSession(sess, params.authParams)
	return
}

func checkIpsecRekeyResponse(sess *Session, params *childSaParams) (espSpiR protocol.Spi, err error) {
	if params.tsI == nil || params.tsR == nil {
		err = errors.Errorf("CREATE_CHILD_SA response: selectors are missing")
		return
	}
	espSpiR, _, err = checkSelectorsForSession(sess, params.authParams)
	return
}
