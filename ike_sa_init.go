package ike

import (
	"math/big"

	"github.com/msgboxio/ike/protocol"
)

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
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     p.proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         p.nonce,
	})
	return init
}

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
