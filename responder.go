package ike

import (
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/state"
	"msgbox.io/log"
)

type Responder struct {
	Session
	remoteAddr net.Addr
}

func NewResponder(parent context.Context, ids Identities, conn net.Conn, remoteAddr net.Addr, remote, local net.IP, initI *Message) (*Responder, error) {
	cxt, cancel := context.WithCancel(parent)

	if !EnsurePayloads(initI, InitPayloads) {
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
	spiI, err := getPeerSpi(initI, IKE)
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
			events:   make(chan stateEvents, 10),
			messages: make(chan *Message, 10),
		},
		remoteAddr: remoteAddr,
	}
	go run(&o.Session)

	o.fsm = state.MakeFsm(o, state.SmrInit, cxt)
	return o, nil
}

func (o *Responder) HandleMessage(m *Message) { o.messages <- m }

func (o *Responder) SendIkeSaInit() {
	// make response message
	initR := makeInit(initParams{
		isInitiator:   o.tkm.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          o.IkeSpiR,
		proposals:     []*SaProposal{o.cfg.ProposalIke},
		nonce:         o.tkm.Nr,
		dhTransformId: o.tkm.suite.dhGroup.DhTransformId,
		dhPublic:      o.tkm.DhPublic,
	})
	// encode & send
	var err error
	o.initRb, err = EncodeTx(initR, nil, o.conn, o.remoteAddr, false)
	if err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	o.msgId++
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof("IKE SA Established: [%s]%#x<=>%#x[%s]",
		o.remoteAddr,
		o.IkeSpiI,
		o.IkeSpiR,
		o.conn.LocalAddr())
}

func (o *Responder) SendIkeAuth() {
	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	signed1 := append(o.initRb, o.tkm.Ni.Bytes()...)
	o.cfg.ProposalEsp.Spi = o.EspSpiR
	prop := []*SaProposal{o.cfg.ProposalEsp}
	authR := makeAuth(o.IkeSpiI, o.IkeSpiR, prop, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm)
	_, err := EncodeTx(authR, o.tkm, o.conn, o.remoteAddr, false)
	if err != nil {
		log.Error(err)
		o.cancel(err)
		return
	}
	log.Infof("ESP SA Established: %#x<=>%#x; Selectors: %s<=>%s", o.EspSpiI, o.EspSpiR, o.cfg.TsI, o.cfg.TsR)
}

func (o *Responder) HandleSaInit(m interface{}) {
	msg := m.(*Message)
	o.initIb = msg.Data
	o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_SA_INIT_SUCCESS})
}
func (o *Responder) HandleSaAuth(m interface{}) {
	msg := m.(*Message)
	// decrypt
	if err := o.handleEncryptedMessage(msg); err != nil {
		log.Error(err)
		return
	}
	if !EnsurePayloads(msg, AuthIPayloads) {
		err := errors.New("essential payload is missing from auth message")
		log.Error(err)
		return
	}
	// authenticate peer
	if !authenticateI(msg, o.initIb, o.tkm) {
		err := errors.New("could not authenticate")
		log.Error(err)
		return
	}
	// get peer spi
	peerSpi, err := getPeerSpi(msg, ESP)
	if err != nil {
		log.Error(err)
		return
	}
	o.EspSpiI = append([]byte{}, peerSpi...)

	// props := msg.Payloads.Get(PayloadTypeSA).(*SaPayload).Proposals
	// tsI := msg.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload).Selectors
	// tsR := msg.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload).Selectors
	// Todo Check tsi & r
	o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_AUTH_SUCCESS})
}
