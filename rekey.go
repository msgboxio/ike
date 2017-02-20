package ike

import (
	"errors"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
)

var ErrorRekeyRequired = errors.New("Rekey Required")

//  SK {SA, Ni, KEi} - ike sa
func (o *Session) SendIkeSaRekey(newTkm *Tkm) {
	newIkeSpiI := MakeSpi()
	init := makeChildSa(&childSaParams{
		isInitiator:   o.isInitiator,
		ikeSpiI:       o.IkeSpiI,
		ikeSpiR:       o.IkeSpiR,
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
	_, err := init.Encode(o.tkm, o.isInitiator, o.Logger)
	if err != nil {
		o.Logger.Error(err)
		return
	}
	// TODO - send
}

//  SK {SA, Nr, KEr} - ike sa
func HandleSaRekey(o *Session, newTkm *Tkm, msg interface{}) error {
	m := msg.(*Message)
	params, err := parseChildSa(m)
	if err != nil {
		return err
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		o.Logger.Error(err)
		return nil
	}
	if params.dhPublic != nil {
		if err := newTkm.DhGenerateKey(params.dhPublic); err != nil {
			o.Logger.Error(err)
			return nil
		}
	}
	// set Nr
	newTkm.Nr = params.nonce
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
	o.PostEvent(&state.StateEvent{})
	return nil
}
