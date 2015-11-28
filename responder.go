package ike

import (
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/protocol"
	"msgbox.io/ike/state"
	"msgbox.io/log"
)

type Responder struct {
	Session

	initIb, initRb []byte
	remoteAddr     net.Addr
}

func NewResponder(parent context.Context, ids Identities, conn net.Conn, remoteAddr net.Addr, remote, local net.IP, initI *Message) (*Responder, error) {
	cxt, cancel := context.WithCancel(parent)

	if !initI.EnsurePayloads(InitPayloads) {
		err := errors.New("essential payload is missing from init message")
		cancel(err)
		return nil, err
	}
	tkm, err := newTkmFromInit(initI, ids)
	if err != nil {
		cancel(err)
		return nil, err
	}
	cfg, err := NewClientConfigFromInit(initI)
	if err != nil {
		cancel(err)
		return nil, err
	}
	// TODO - check ike proposal
	spiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		cancel(err)
		return nil, err
	}
	o := &Responder{
		Session: Session{
			Context:  cxt,
			cancel:   cancel,
			conn:     conn,
			remote:   remote,
			local:    local,
			tkm:      tkm,
			cfg:      cfg,
			IkeSpiI:  spiI,
			IkeSpiR:  MakeSpi(),
			EspSpiR:  MakeSpi()[:4],
			messages: make(chan *Message, 10),
		},
		remoteAddr: remoteAddr,
	}
	go run(&o.Session)

	o.fsm = state.NewFsm(state.AddTransitions(state.ResponderTransitions(o), state.CommonTransitions(o)))
	go o.fsm.Run()

	return o, nil
}

func (o *Responder) HandleMessage(m *Message) { o.messages <- m }

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
	o.initRb, err = EncodeTx(initR, nil, o.conn, o.remoteAddr, false)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.msgId++
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof("IKE SA Established: [%s]%#x<=>%#x[%s]",
		o.remoteAddr,
		o.IkeSpiI,
		o.IkeSpiR,
		o.conn.LocalAddr())
	return
}

func (o *Responder) SendAuth() (s state.StateEvent) {
	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	o.cfg.ProposalEsp.Spi = o.EspSpiR
	prop := []*protocol.SaProposal{o.cfg.ProposalEsp}
	signed1 := append(o.initRb, o.tkm.Ni.Bytes()...)
	authR := makeAuth(o.IkeSpiI, o.IkeSpiR, prop, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm, o.cfg.IsTransportMode)
	_, err := EncodeTx(authR, o.tkm, o.conn, o.remoteAddr, false)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	return
}

func (o *Responder) CheckInit(m interface{}) (s state.StateEvent) {
	s.Event = state.INIT_FAIL
	msg := m.(*Message)
	o.initIb = msg.Data
	// TODO Check message
	s.Event = state.SUCCESS
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
	if !msg.EnsurePayloads(AuthIPayloads) {
		err := errors.New("essential payload is missing from auth message")
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
	peerSpi, err := getPeerSpi(msg, protocol.ESP)
	if err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	o.EspSpiI = append([]byte{}, peerSpi...)
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
