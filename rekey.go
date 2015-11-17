package ike

import (
	"errors"

	"msgbox.io/ike/crypto"
	"msgbox.io/ike/protocol"
	"msgbox.io/ike/state"
	"msgbox.io/log"
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
	suite, err := crypto.NewCipherSuite(o.cfg.ProposalIke.Transforms)
	if err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	if o.newTkm, err = NewTkmInitiator(suite, o.tkm.ids); err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	o.newIkeSpiI = MakeSpi()
	o.cfg.ProposalIke.Spi = o.newIkeSpiI
	init := makeIkeChildSa(childSaParams{
		isInitiator:   o.tkm.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          o.IkeSpiR,
		proposals:     []*protocol.SaProposal{o.cfg.ProposalIke},
		nonce:         o.newTkm.Ni,
		dhTransformId: o.newTkm.suite.DhGroup.DhTransformId,
		dhPublic:      o.newTkm.DhPublic,
	})
	init.IkeHeader.MsgId = o.msgId
	// use old tkm to encrypt & sign
	o.initIb, err = EncodeTx(init, o.tkm, o.conn, o.conn.RemoteAddr(), true)
	if err != nil {
		log.Error(err)
		o.cancel(err)
	}
	o.msgId++
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
	if !m.EnsurePayloads(InitPayloads) {
		err := errors.New("essential payload is missing from Ike Sa rekey message")
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
	log.Infof("NEW IKE SA Established: [%s]%#x<=>%#x[%s]",
		o.conn.LocalAddr(),
		o.newIkeSpiI,
		o.newIkeSpiR,
		o.conn.RemoteAddr())
	// save Data
	o.initRb = m.Data
	o.fsm.PostEvent(state.IkeEvent{Id: state.CREATE_CHILD_SA_SUCCESS})
}
