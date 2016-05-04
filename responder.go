package ike

import (
	"errors"

	"github.com/msgboxio/context"
	"github.com/msgboxio/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
)

type Responder struct {
	Session
}

func NewResponder(parent context.Context, ids Identities, initI *Message) (*Responder, error) {
	if err := initI.EnsurePayloads(InitPayloads); err != nil {
		return nil, err
	}
	tkm, err := newTkmFromInit(initI, ids)
	if err != nil {
		return nil, err
	}
	cfg, err := NewClientConfigFromInit(initI)
	if err != nil {
		return nil, err
	}
	// TODO - check ike proposal
	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}
	cxt, cancel := context.WithCancel(parent)
	o := &Responder{
		Session: Session{
			Context:     cxt,
			cancel:      cancel,
			isResponder: true,
			remote:      initI.RemoteIp,
			local:       initI.LocalIp,
			tkm:         tkm,
			cfg:         cfg,
			IkeSpiI:     ikeSpiI,
			IkeSpiR:     MakeSpi(),
			EspSpiR:     MakeSpi()[:4],
			incoming:    make(chan *Message, 10),
			outgoing:    make(chan []byte, 10),
		},
	}
	go run(&o.Session)

	o.fsm = state.NewFsm(state.AddTransitions(state.ResponderTransitions(o), state.CommonTransitions(o)))
	go o.fsm.Run()

	return o, nil
}

func (o *Responder) CheckInit(m interface{}) (s state.StateEvent) {
	s.Event = state.INIT_FAIL
	msg := m.(*Message)
	o.initIb = msg.Data
	// TODO Check message
	s.Event = state.SUCCESS
	return
}

func (o *Responder) SendInit() (s state.StateEvent) {
	// make response message
	initR := makeInit(initParams{
		isInitiator:   o.tkm.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          o.IkeSpiR,
		proposals:     []*protocol.SaProposal{o.cfg.ProposalIke},
		nonce:         o.tkm.Nr,
		dhTransformId: o.tkm.suite.DhGroup.DhTransformId,
		dhPublic:      o.tkm.DhPublic,
	})
	// encode & send
	var err error
	o.initRb, err = initR.Encode(nil)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- o.initRb

	o.msgId++
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof("IKE SA Established: [%s]%#x<=>%#x[%s]",
		o.remote,
		o.IkeSpiI,
		o.IkeSpiR,
		o.local)
	return
}

func (o *Responder) CheckAuth(m interface{}) (s state.StateEvent) {
	// initialize return
	s.Event = state.AUTH_FAIL
	// get message
	msg := m.(*Message)
	// decrypt
	if err := o.handleEncryptedMessage(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	if err := msg.EnsurePayloads(AuthIPayloads); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// authenticate peer
	if !authenticateI(msg, o.initIb, o.tkm) {
		err := errors.New("could not authenticate")
		log.Error(err)
		s.Data = err
		return
	}
	// get peer spi
	espSpiI, err := getPeerSpi(msg, protocol.ESP)
	if err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	o.EspSpiI = append([]byte{}, espSpiI...)
	// final check
	if err := o.checkSa(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// load additional configs
	if err = o.cfg.AddFromAuth(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - check IPSEC selectors & config
	s.Event = state.SUCCESS
	// move to MATURE state
	o.fsm.Event(state.StateEvent{Event: state.SUCCESS})
	return
}

func (o *Responder) SendAuth() (s state.StateEvent) {
	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	o.cfg.ProposalEsp.Spi = o.EspSpiR
	prop := []*protocol.SaProposal{o.cfg.ProposalEsp}
	signed1 := append(o.initRb, o.tkm.Ni.Bytes()...)
	authR := makeAuth(o.IkeSpiI, o.IkeSpiR, prop, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm, o.cfg.IsTransportMode)
	// encode & send
	authRb, err := authR.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- authRb
	return
}
