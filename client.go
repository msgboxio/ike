package ike

import (
	"bytes"
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/state"
	"msgbox.io/log"
	"msgbox.io/packets"
)

type stateEvents int

const (
	ikeInit stateEvents = iota + 1
	ikeAuth
	ikeCrl
	ikeSa
)

// Initiator will run over a socket
// until asked to stop,
// or when it gives up due to failure
type Initiator struct {
	context.Context
	cancel context.CancelFunc

	tkm *Tkm
	cfg *ClientCfg

	udp    *net.UDPConn
	remote *net.UDPAddr

	initIb, initRb []byte

	events   chan stateEvents
	messages chan *Message

	fsm *state.Fsm
}

func NewInitiator(parent context.Context, remote *net.UDPAddr, cfg *ClientCfg) (o *Initiator) {
	cxt, cancel := context.WithCancel(parent)

	o = &Initiator{
		Context:  cxt,
		cancel:   cancel,
		remote:   remote,
		events:   make(chan stateEvents, 10),
		messages: make(chan *Message, 10),
	}

	var err error
	// use random local address
	if o.udp, err = net.DialUDP("udp4", nil, remote); err != nil {
		log.Error(err)
		cancel(err)
		return
	}
	log.Infof("socket connected: %s", o.udp)

	o.cfg = cfg
	suite := NewCipherSuite(o.cfg.IkeTransforms)
	if o.tkm, err = NewTkmInitiator(suite); err != nil {
		log.Error(err)
		cancel(err)
		return
	}

	go runInitiator(o)
	go runReader(o)

	o.fsm = state.MakeFsm(o, cxt)
	o.fsm.PostEvent(state.IkeEvent{Id: state.CONNECT})
	return
}

func (o *Initiator) SendIkeSaInit() {
	// send IKE_SA_INIT
	prop := []*SaProposal{o.cfg.ProposalIke}
	init := MakeInit(o.cfg.IkeSpiI, Spi{}, prop, o.tkm)
	var err error
	o.initIb, err = EncodeTx(init, o.tkm, o.udp, o.remote, true)
	if err != nil {
		log.Error(err)
		o.cancel(err)
	}
}
func (o *Initiator) SendIkeAuth() {
	signed1 := append(o.initIb, o.tkm.Nr.Bytes()...)
	porp := []*SaProposal{o.cfg.ProposalEsp}
	authI := MakeAuth(o.cfg.IkeSpiI, o.cfg.IkeSpiR, porp, o.cfg.TsI, o.cfg.TsR, signed1, o.tkm)
	if _, err := EncodeTx(authI, o.tkm, o.udp, o.remote, true); err != nil {
		log.Error(err)
		o.cancel(err)
	}
}
func (o *Initiator) DownloadCrl()    { o.events <- ikeCrl }
func (o *Initiator) InstallChildSa() { o.events <- ikeSa }

func (o *Initiator) HandleSaInitResponse(msg interface{}) (err error) {
	m := msg.(*Message)
	log.V(1).Infof("Handling %s: payloads %s", m.IkeHeader.ExchangeType, *(m.Payloads))
	// we know what cryptographyc algorithms peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if !EnsurePayloads(m, InitPayloads) {
		err = errors.New("essential payload is missing from init message")
		log.Error(err)
		return
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := m.Payloads.Get(PayloadTypeKE).(*KePayload)
	if err = o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Error(err)
		return
	}
	// set Nr
	no := m.Payloads.Get(PayloadTypeNonce).(*NoncePayload)
	o.tkm.Nr = no.Nonce
	// set spiR
	copy(o.cfg.IkeSpiR[:], m.IkeHeader.SpiR[:])
	// create rest of ike sa
	o.tkm.IsaCreate(o.cfg.IkeSpiI[:], o.cfg.IkeSpiR[:])
	o.tkm.SetSecret([]byte("ak@msgbox.io"), []byte("foo"))
	o.initRb = m.data
	return
}

func (o *Initiator) HandleSaAuthResponse(msg interface{}) (err error) {
	m := msg.(*Message)
	log.V(1).Infof("Handling %s: payloads %s", m.IkeHeader.ExchangeType, *(m.Payloads))
	if m.IkeHeader.NextPayload == PayloadTypeSK {
		b, err := o.tkm.VerifyDecrypt(m.data)
		if err != nil {
			return err
		}
		sk := m.Payloads.Get(PayloadTypeSK)
		if err = m.decodePayloads(b, sk.NextPayloadType()); err != nil {
			return err
		}
	}
	if !EnsurePayloads(m, AuthRPayloads) {
		err = errors.New("essential payload is missing from auth message")
		return
	}
	// authenticate peer
	if !authenticateR(m, o.initRb, o.tkm) {
		err = errors.New("could not authenticate")
		return
	}
	log.V(1).Infof("Handling %s: decrypted payloads %s", m.IkeHeader.ExchangeType, *(m.Payloads))
	// TODO - check other parameters
	spi, _ := packets.ReadB32(o.cfg.EspSpi, 0)
	log.Infof("sa Established: %x", spi)
	// TODO install child sa
	return nil
}

func (o *Initiator) Notify(ie IkeError) {}

func runInitiator(o *Initiator) {
done:
	for {
		select {
		case <-o.Done():
			break done
		case evt := <-o.events:
			switch evt {
			case ikeSa:
			}
		case msg := <-o.messages:
			evt := state.IkeEvent{Message: msg}
			switch msg.IkeHeader.ExchangeType {
			case IKE_SA_INIT:
				evt.Id = state.IKE_SA_INIT_RESPONSE
				o.fsm.PostEvent(evt)
			case IKE_AUTH:
				evt.Id = state.IKE_AUTH_RESPONSE
				o.fsm.PostEvent(evt)
			case CREATE_CHILD_SA:
				evt.Id = state.IKE_REKEY
				o.fsm.PostEvent(evt)
			}
		}
	}
	o.udp.Close()
	close(o.events)
	close(o.messages)
}

func runReader(o *Initiator) {
	for {
		b, from, err := readPacket(o.udp)
		if err != nil {
			log.Error(err)
			break
		}
		if o.remote != nil && o.remote.String() != from.String() {
			log.Errorf("from different address: %s", from)
			continue
		}
		msg := &Message{}
		if err := msg.decodeHeader(b); err != nil {
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		if len(b) < int(msg.IkeHeader.MsgLength) {
			log.V(LOG_CODEC).Info("")
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		if spi := msg.IkeHeader.SpiI[:]; !bytes.Equal(spi, o.cfg.IkeSpiI[:]) {
			log.Errorf("different initiator Spi %s", spi)
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		msg.Payloads = makePayloads()
		if err = msg.decodePayloads(b[IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
			o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		// decrypt later
		msg.data = b
		o.messages <- msg
	}
}
