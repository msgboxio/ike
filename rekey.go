package ike

import (
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

// rekeying can be started by either end

type ReKeySession struct {
	Session

	initIb, initRb         []byte
	newIkeSpiI, newIkeSpiR protocol.Spi
	newTkm                 *Tkm
}

//  SK {SA, Ni, KEi} - ike sa
func (o *ReKeySession) SendIkeSaRekey() {
	var err error
	suite, err := crypto.NewCipherSuite(o.cfg.ProposalIke)
	if err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	espSuite, err := crypto.NewCipherSuite(o.cfg.ProposalIke)
	if err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	if o.newTkm, err = NewTkmInitiator(suite, espSuite); err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	o.newIkeSpiI = MakeSpi()
	init := makeIkeChildSa(childSaParams{
		isInitiator:   o.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          o.IkeSpiR,
		proposals:     ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.newIkeSpiI),
		nonce:         o.newTkm.Ni,
		dhTransformId: o.newTkm.suite.DhGroup.TransformId(),
		dhPublic:      o.newTkm.DhPublic,
	})
	var msgId uint32
	if o.isInitiator {
		msgId = o.msgIdReq
	} else {
		msgId = o.msgIdResp
	}
	init.IkeHeader.MsgId = msgId
	// encode & send
	o.initIb, err = init.Encode(o.tkm, o.isInitiator)
	if err != nil {
		log.Error(err)
		return
	}
	o.outgoing <- o.initIb
}

//  SK {SA, Nr, KEr} - ike sa
func (o *ReKeySession) HandleSaRekey(msg interface{}) {
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		return
	}
	if m.IkeHeader.Flags != protocol.RESPONSE {
		return // TODO handle this later
	}
	if tsi := m.Payloads.Get(protocol.PayloadTypeTSi); tsi != nil {
		log.V(1).Info("received CREATE_CHILD_SA for child sa")
		return // TODO
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		log.Error(err)
		return
	}
	// TODO - currently dont support different prfs from original
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.newTkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Error(err)
		return
	}
	// set Nr
	no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	o.newTkm.Nr = no.Nonce
	// get new IKE spi
	peerSpi, err := getPeerSpi(m, protocol.IKE)
	if err != nil {
		log.Error(err)
		return
	}
	o.newIkeSpiR = append([]byte{}, peerSpi...)
	// create rest of ike sa
	o.newTkm.IsaCreate(o.newIkeSpiI, o.newIkeSpiR, o.tkm.skD)
	log.Infof("NEW IKE SA Established: %#x<=>%#x",
		o.newIkeSpiI,
		o.newIkeSpiR)
	// save Data
	o.initRb = m.Data
	o.PostEvent(&state.StateEvent{})
}
