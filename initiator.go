package ike

import (
	"net"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

type Initiator struct {
	Session
}

func NewInitiator(parent context.Context, ids Identities, remote net.IP, cfg *Config) *Initiator {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		log.Error(err)
		return nil
	}
	if suite == nil {
		panic("suite must not be null")
	}
	var tkm *Tkm
	if tkm, err = NewTkmInitiator(suite, ids); err != nil {
		log.Error(err)
		return nil
	}

	cxt, cancel := context.WithCancel(parent)

	o := &Initiator{
		Session: Session{
			Context: cxt,
			cancel:  cancel,
			tkm:     tkm,
			cfg:     cfg,
			remote:  remote,
			// local:    local,
			IkeSpiI:  MakeSpi(),
			EspSpiI:  MakeSpi()[:4],
			incoming: make(chan *Message, 10),
			outgoing: make(chan []byte, 10),
		},
	}
	go run(&o.Session)

	o.fsm = state.NewFsm(state.AddTransitions(state.InitiatorTransitions(o), state.CommonTransitions(o)))
	go o.fsm.Run()
	o.fsm.Event(state.StateEvent{Event: state.SMI_START})
	return o
}

func (o *Initiator) HandleIkeSaInit(msg interface{}) (s state.StateEvent) {
	s.Event = state.INIT_FAIL
	// response
	m := msg.(*Message)
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if err := m.EnsurePayloads(InitPayloads); err != nil {
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
	log.Infof("IKE SA INITIALISED: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	// save Data
	o.initRb = m.Data
	s.Event = state.SUCCESS
	return
}

func (o *Initiator) HandleIkeAuth(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	// response
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	if err := m.EnsurePayloads(AuthRPayloads); err != nil {
		// notification is recoverable
		for _, n := range m.Payloads.GetNotifications() {
			if err, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
				s.Data = err
				return
			}
		}
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
	log.Infof("IKE SA CREATED: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	s.Event = state.SUCCESS
	// currently in STATE_AUTH, move to STATE_MATURE state
	o.fsm.Event(state.StateEvent{Event: state.SUCCESS, Data: m})
	return
}

func (o *Initiator) CheckSa(msg interface{}) (s state.StateEvent) {
	m := msg.(*Message)
	// get peer spi
	espSpiR, err := getPeerSpi(m, protocol.ESP)
	if err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	o.EspSpiR = append([]byte{}, espSpiR...)
	// final check
	if err := o.checkSa(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// load additional configs
	if err = o.cfg.AddFromAuth(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	s.Event = state.SUCCESS
	return
}
