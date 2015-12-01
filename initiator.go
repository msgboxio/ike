package ike

import (
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/crypto"
	"msgbox.io/ike/protocol"
	"msgbox.io/ike/state"
	"msgbox.io/log"
)

type Initiator struct {
	Session
}

func NewInitiator(parent context.Context, ids Identities, remote, local net.Addr, cfg *ClientCfg) (o *Initiator) {
	cxt, cancel := context.WithCancel(parent)

	o = &Initiator{
		Session: Session{
			Context:  cxt,
			cancel:   cancel,
			remote:   remote,
			local:    local,
			IkeSpiI:  MakeSpi(),
			EspSpiI:  MakeSpi()[:4],
			incoming: make(chan *Message, 10),
			outgoing: make(chan []byte, 10),
		},
	}

	var err error

	o.cfg = cfg
	suite, err := crypto.NewCipherSuite(o.cfg.ProposalIke.Transforms)
	if err != nil {
		log.Error(err)
		cancel(err)
		return
	}
	if o.tkm, err = NewTkmInitiator(suite, ids); err != nil {
		log.Error(err)
		cancel(err)
		return
	}

	go run(&o.Session)

	o.fsm = state.NewFsm(state.AddTransitions(state.InitiatorTransitions(o), state.CommonTransitions(o)))
	go o.fsm.Run()
	o.fsm.Event(state.StateEvent{Event: state.SMI_START})
	return
}

func (o *Initiator) SendInit() (s state.StateEvent) {
	// IKE_SA_INIT
	init := makeInit(initParams{
		isInitiator:   o.tkm.isInitiator,
		spiI:          o.IkeSpiI,
		spiR:          make([]byte, 8),
		proposals:     []*protocol.SaProposal{o.cfg.ProposalIke},
		nonce:         o.tkm.Ni,
		dhTransformId: o.tkm.suite.DhGroup.DhTransformId,
		dhPublic:      o.tkm.DhPublic,
	})
	init.IkeHeader.MsgId = o.msgId
	// encode & send
	var err error
	o.initIb, err = init.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- o.initIb
	o.msgId++
	return
}

func (o *Initiator) CheckInit(msg interface{}) (s state.StateEvent) {
	s.Event = state.INIT_FAIL
	// response
	m := msg.(*Message)
	// we know what cryptographyc algorithms peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if !m.EnsurePayloads(InitPayloads) {
		err := errors.New("essential payload is missing from init message")
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// set Nr
	no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	o.tkm.Nr = no.Nonce
	// set spiR
	o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof("IKE SA Established: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	// save Data
	o.initRb = m.Data
	s.Event = state.SUCCESS
	return
}

func (o *Initiator) SendAuth() (s state.StateEvent) {
	// IKE_AUTH
	o.cfg.ProposalEsp.Spi = o.EspSpiI
	porp := []*protocol.SaProposal{o.cfg.ProposalEsp}
	log.Infof("SA selectors: %s<=>%s", o.cfg.TsI, o.cfg.TsR)
	// tkm.Auth  needs to be called for both initiator & responder from the initator. so
	signed1 := append(o.initIb, o.tkm.Nr.Bytes()...)
	authI := makeAuth(o.IkeSpiI, o.IkeSpiR, porp, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm, o.cfg.IsTransportMode)
	authI.IkeHeader.MsgId = o.msgId
	// encode & send
	authIb, err := authI.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- authIb
	o.msgId++
	return
}

func (o *Initiator) CheckAuth(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	// response
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	if !m.EnsurePayloads(AuthRPayloads) {
		for _, n := range m.Payloads.GetNotifications() {
			if err, ok := protocol.GetIkeError(n.NotificationType); ok {
				s.Data = err
				return
			}
		}
		err := errors.New("essential payload is missing from auth message")
		log.Error(err)
		s.Data = err
		return
	}
	// authenticate peer
	if !authenticateR(m, o.initRb, o.tkm) {
		log.Error(protocol.AUTHENTICATION_FAILED)
		s.Data = protocol.AUTHENTICATION_FAILED
		return
	}
	// get peer spi
	peerSpi, err := getPeerSpi(m, protocol.ESP)
	if err != nil {
		return
	}
	o.EspSpiR = append([]byte{}, peerSpi...)
	// final check
	if err := o.checkSa(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	s.Event = state.SUCCESS
	return
}
