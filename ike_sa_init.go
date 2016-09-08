package ike

import "github.com/msgboxio/ike/protocol"

// IKE_SA_INIT

func InitMsg(tkm *Tkm, ikeSpiI, ikeSpiR []byte, msgID uint32, cfg *Config) ([]byte, error) {
	nonce := tkm.Ni
	if !tkm.isInitiator {
		nonce = tkm.Nr
	}
	init := makeInit(initParams{
		isInitiator:   tkm.isInitiator,
		spiI:          ikeSpiI,
		spiR:          ikeSpiR,
		proposals:     ProposalFromTransform(protocol.IKE, cfg.ProposalIke, ikeSpiI),
		nonce:         nonce,
		dhTransformId: tkm.suite.DhGroup.DhTransformId,
		dhPublic:      tkm.DhPublic,
	})
	init.IkeHeader.MsgId = msgID
	// encode
	initB, err := init.Encode(tkm)
	if err != nil {
		return nil, err
	}
	return initB, nil
}
