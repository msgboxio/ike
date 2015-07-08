package ike

import (
	"bytes"
	"errors"
	"net"
	"time"

	"msgbox.io/context"
	"msgbox.io/ike/state"
	"msgbox.io/log"
)

// Initiator will run over a socket
// until asked to stop,
// or when it gives up due to failure
type Initiator struct {
	Session
}

func NewInitiator(parent context.Context, ids Identities, conn net.Conn, remote, local net.IP, cfg *ClientCfg) (o *Initiator) {
	cxt, cancel := context.WithCancel(parent)

	o = &Initiator{
		Session{
			Context:  cxt,
			cancel:   cancel,
			conn:     conn,
			remote:   remote,
			local:    local,
			events:   make(chan stateEvents, 10),
			messages: make(chan *Message, 10),
		},
	}

	var err error

	o.cfg = cfg
	suite := NewCipherSuite(o.cfg.IkeTransforms)
	if o.tkm, err = NewTkmInitiator(suite, ids); err != nil {
		log.Error(err)
		cancel(err)
		return
	}

	go run(&o.Session)
	go runReader(o, conn.RemoteAddr())

	o.fsm = state.MakeFsm(o, state.SmiInit, cxt)
	o.fsm.PostEvent(state.IkeEvent{Id: state.CONNECT})
	return
}

func (o *Initiator) SendIkeSaInit() {
	// IKE_SA_INIT
	init := makeInit(initParams{
		isInitiator:   o.tkm.isInitiator,
		spiI:          o.cfg.IkeSpiI,
		spiR:          make([]byte, 8),
		proposals:     []*SaProposal{o.cfg.ProposalIke},
		nonce:         o.tkm.Ni,
		dhTransformId: o.tkm.suite.dhGroup.DhTransformId,
		dhPublic:      o.tkm.DhPublic,
	})
	init.IkeHeader.MsgId = o.msgId
	var err error
	o.initIb, err = EncodeTx(init, o.tkm, o.conn, o.conn.RemoteAddr(), true)
	if err != nil {
		log.Error(err)
		o.cancel(err)
	}
	o.msgId++
}

func (o *Initiator) SendIkeAuth() {
	// IKE_AUTH
	signed1 := append(o.initIb, o.tkm.Nr.Bytes()...)
	porp := []*SaProposal{o.cfg.ProposalEsp}
	log.Infof("SA selectors: %s<=>%s", o.cfg.TsI, o.cfg.TsR)
	authI := makeAuth(o.cfg.IkeSpiI, o.cfg.IkeSpiR, porp, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm)
	authI.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(authI, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
		o.cancel(err)
	}
	o.msgId++
}

func (o *Initiator) HandleSaInit(msg interface{}) {
	// response
	m := msg.(*Message)
	// we know what cryptographyc algorithms peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if !EnsurePayloads(m, InitPayloads) {
		err := errors.New("essential payload is missing from init message")
		log.Error(err)
		return
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := m.Payloads.Get(PayloadTypeKE).(*KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Error(err)
		return
	}
	// set Nr
	no := m.Payloads.Get(PayloadTypeNonce).(*NoncePayload)
	o.tkm.Nr = no.Nonce
	// set spiR
	o.cfg.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	// create rest of ike sa
	o.tkm.IsaCreate(o.cfg.IkeSpiI, o.cfg.IkeSpiR)
	log.Infof("IKE SA Established: %#x<=>%#x", o.cfg.IkeSpiI, o.cfg.IkeSpiR)
	// save Data
	o.initRb = m.Data
	o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_SA_INIT_SUCCESS})
	return
}

func (o *Initiator) HandleSaAuth(msg interface{}) {
	// response
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		return
	}
	if !EnsurePayloads(m, AuthRPayloads) {
		err := errors.New("essential payload is missing from auth message")
		log.Error(err)
		return
	}
	// authenticate peer
	if !authenticateR(m, o.initRb, o.tkm) {
		err := errors.New("could not authenticate")
		log.Error(err)
		return
	}
	// get peer spi
	peerSpi, err := getPeerSpi(m)
	if err != nil {
		log.Error(err)
		return
	}
	o.cfg.EspSpiR = append([]byte{}, peerSpi...)

	tsi := m.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload)
	tsr := m.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload)
	log.Infof("ESP SA Established: %#x<=>%#x; Selectors: %s<=>%s", o.cfg.EspSpiI, o.cfg.EspSpiR, tsi.Selectors, tsr.Selectors)
	if note := m.Payloads.Get(PayloadTypeN); note != nil {
		switch notify := note.(*NotifyPayload); notify.NotificationType {
		case AUTH_LIFETIME:
			log.Infof("Lifetime: %v", notify.NotificationMessage)
			time.AfterFunc(notify.NotificationMessage.(time.Duration), func() {
				o.fsm.PostEvent(state.IkeEvent{Id: state.MSG_IKE_TERMINATE})
				// o.fsm.PostEvent(state.IkeEvent{Id: state.MSG_IKE_REKEY})
			})
		}
	}
	o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_AUTH_SUCCESS})
}

func runReader(o *Initiator, remoteAddr net.Addr) {
	for {
		b, _, err := ReadPacket(o.conn, remoteAddr, true)
		if err != nil {
			log.Error(err)
			break
		}
		// if o.remote != nil && o.remote.String() != from.String() {
		// 	log.Errorf("from different address: %s", from)
		// 	continue
		// }
		msg := &Message{}
		if err := msg.DecodeHeader(b); err != nil {
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		if len(b) < int(msg.IkeHeader.MsgLength) {
			log.V(LOG_CODEC).Info("")
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		if spi := msg.IkeHeader.SpiI; !bytes.Equal(spi, o.cfg.IkeSpiI) {
			log.Errorf("different initiator Spi %s", spi)
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		msg.Payloads = MakePayloads()
		if err = msg.DecodePayloads(b[IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		// decrypt later
		msg.Data = b
		o.messages <- msg
	}
}
