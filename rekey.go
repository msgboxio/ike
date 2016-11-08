package ike

import (
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
)

//  SK {SA, Ni, KEi} - ike sa
func (o *Session) SendIkeSaRekey() {
	suite, err := crypto.NewCipherSuite(o.cfg.ProposalIke, o.Logger)
	if err != nil {
		o.Logger.Error(err)
		o.cancel(err)
		return
	}
	espSuite, err := crypto.NewCipherSuite(o.cfg.ProposalIke, o.Logger)
	if err != nil {
		o.Logger.Error(err)
		o.cancel(err)
		return
	}
	newTkm, err := NewTkmInitiator(suite, espSuite)
	if err != nil {
		o.Logger.Error(err)
		o.cancel(err)
		return
	}
	newIkeSpiI := MakeSpi()
	init := makeIkeChildSa(childSaParams{
		isInitiator:   o.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          o.IkeSpiR,
		proposals:     ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, newIkeSpiI),
		nonce:         newTkm.Ni,
		dhTransformId: newTkm.suite.DhGroup.TransformId(),
		dhPublic:      newTkm.DhPublic,
	})
	msgId := o.msgIdResp
	if o.isInitiator {
		msgId = o.msgIdReq
	}
	init.IkeHeader.MsgId = msgId
	// encode & send
	_, err = init.Encode(o.tkm, o.isInitiator, o.Logger)
	if err != nil {
		o.Logger.Error(err)
		return
	}
	// TODO - send
}

//  SK {SA, Nr, KEr} - ike sa
func (o *Session) HandleSaRekey(msg interface{}) {
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		o.Logger.Error(err)
		return
	}
	if m.IkeHeader.Flags != protocol.RESPONSE {
		return // TODO handle this later
	}
	if tsi := m.Payloads.Get(protocol.PayloadTypeTSi); tsi != nil {
		o.Logger.Info("received CREATE_CHILD_SA for child sa")
		return // TODO
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		o.Logger.Error(err)
		return
	}
	// TODO - currently dont support different prfs from original
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		o.Logger.Error(err)
		return
	}
	// set Nr
	no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	o.tkm.Nr = no.Nonce
	// get new IKE spi
	peerSpi, err := getPeerSpi(m, protocol.IKE)
	if err != nil {
		o.Logger.Error(err)
		return
	}
	o.IkeSpiR = append([]byte{}, peerSpi...)
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, o.tkm.skD)
	o.Logger.Infof("NEW IKE SA Established: %#x<=>%#x",
		o.IkeSpiI,
		o.IkeSpiR)
	// save Data
	o.initRb = m.Data
	o.PostEvent(&state.StateEvent{})
}
