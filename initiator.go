package ike

import (
	"bytes"
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/platform"
	"msgbox.io/ike/state"
	"msgbox.io/log"
	"msgbox.io/packets"
)

type stateEvents int

const (
	ikeCrl stateEvents = iota + 1
	installChildSa
	removeChildSa
)

// Initiator will run over a socket
// until asked to stop,
// or when it gives up due to failure
type Initiator struct {
	context.Context
	cancel context.CancelFunc

	tkm *Tkm
	cfg *ClientCfg

	conn          net.Conn
	remote, local net.IP

	initIb, initRb []byte

	events   chan stateEvents
	messages chan *Message

	fsm *state.Fsm

	msgId uint32
}

func NewInitiator(parent context.Context, ids Identities, conn net.Conn, remote, local net.IP, cfg *ClientCfg) (o *Initiator) {
	cxt, cancel := context.WithCancel(parent)

	o = &Initiator{
		Context:  cxt,
		cancel:   cancel,
		conn:     conn,
		remote:   remote,
		local:    local,
		events:   make(chan stateEvents, 10),
		messages: make(chan *Message, 10),
	}

	var err error

	o.cfg = cfg
	suite := NewCipherSuite(o.cfg.IkeTransforms)
	if o.tkm, err = NewTkmInitiator(suite, ids); err != nil {
		log.Error(err)
		cancel(err)
		return
	}

	go runInitiator(o)
	go runReader(o, conn.RemoteAddr())

	o.fsm = state.MakeFsm(o, cxt)
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
func (o *Initiator) SendSaDeleteResponse() {
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.cfg.IkeSpiI,
		spiR:        o.cfg.IkeSpiR,
		payload: &DeletePayload{
			PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNone},
			ProtocolId:    IKE,
			Spis:          []Spi{o.cfg.IkeSpiR},
		},
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
		o.cancel(err)
	}
	o.events <- removeChildSa
	o.msgId++
}

func (o *Initiator) DownloadCrl()    { o.events <- ikeCrl }
func (o *Initiator) InstallChildSa() { o.events <- installChildSa }

func (o *Initiator) HandleSaInitResponse(msg interface{}) {
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

func (o *Initiator) HandleSaAuthResponse(msg interface{}) {
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
	var peerSpi []byte
	props := m.Payloads.Get(PayloadTypeSA).(*SaPayload).Proposals
	for _, p := range props {
		if !p.isSpiSizeCorrect(len(p.Spi)) {
			log.Errorf("weird spi size :%+v", *p)
		}
		if p.ProtocolId == ESP {
			peerSpi = p.Spi
		}
	}
	if peerSpi == nil {
		err := errors.New("Unknown Peer SPI")
		log.Error(err)
		return
	}
	o.cfg.EspSpiR = peerSpi
	tsi := m.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload)
	tsr := m.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload)
	log.Infof("ESP SA Established: %#x<=>%#x; Selectors: %s<=>%s", o.cfg.EspSpiI, o.cfg.EspSpiR, tsi.Selectors, tsr.Selectors)
	if note := m.Payloads.Get(PayloadTypeN); note != nil {
		switch notify := note.(*NotifyPayload); notify.NotificationType {
		case AUTH_LIFETIME:
			log.Infof("Lifetime: %v", notify.NotificationMessage)
		}
	}
	o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_AUTH_SUCCESS})
}

func (o *Initiator) HandleSaRekey(msg interface{}) {
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		return
	}
	// TODO
}

// close session
func (o *Initiator) HandleSaDead() {
	log.Info("close session")
	o.cancel(context.Canceled)
}

func (o *Initiator) handleInformational(msg *Message) (err error) {
	if err = o.handleEncryptedMessage(msg); err != nil {
		return err
	}
	if del := msg.Payloads.Get(PayloadTypeD); del != nil {
		dp := del.(*DeletePayload)
		if dp.ProtocolId == IKE {
			log.Infof("Peer removed IKE SA : %#x", msg.IkeHeader.SpiI)
			o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_SA_DELETE_REQUEST})
		}
		for _, spi := range dp.Spis {
			if dp.ProtocolId == ESP {
				log.Info("removed ESP SA : %#x", spi)
				// TODO
			}
		}
	}
	return
}

func (o *Initiator) handleEncryptedMessage(m *Message) (err error) {
	if m.IkeHeader.NextPayload == PayloadTypeSK {
		var b []byte
		if b, err = o.tkm.VerifyDecrypt(m.Data); err != nil {
			return err
		}
		sk := m.Payloads.Get(PayloadTypeSK)
		if err = m.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return err
		}
	}
	return
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
			case installChildSa:
				espEi, espAi, espEr, espAr := o.tkm.IpsecSaCreate(o.cfg.IkeSpiI, o.cfg.IkeSpiR)
				SpiI, _ := packets.ReadB32(o.cfg.EspSpiI, 0)
				SpiR, _ := packets.ReadB32(o.cfg.EspSpiR, 0)
				sa := &platform.SaParams{
					Src:     o.local,
					Dst:     o.remote,
					SrcPort: 0,
					DstPort: 0,
					SrcNet:  &net.IPNet{o.local, net.CIDRMask(32, 32)},
					DstNet:  &net.IPNet{o.remote, net.CIDRMask(32, 32)},
					EspEi:   espEi,
					EspAi:   espAi,
					EspEr:   espEr,
					EspAr:   espAr,
					SpiI:    int(SpiI),
					SpiR:    int(SpiR),
				}
				if err := platform.InstallChildSa(sa); err != nil {
					log.Error("Error installing child SA: %v", err)
				}
			case removeChildSa:
				// remove sa
				SpiI, _ := packets.ReadB32(o.cfg.EspSpiI, 0)
				SpiR, _ := packets.ReadB32(o.cfg.EspSpiR, 0)
				sa := &platform.SaParams{
					SpiI: int(SpiI),
					SpiR: int(SpiR),
				}
				if err := platform.RemoveChildSa(sa); err != nil {
					log.Error("Error removing child SA: %v", err)
				}
				o.fsm.PostEvent(state.IkeEvent{Id: state.MSG_IKE_TERMINATE})
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
			// case CREATE_CHILD_SA:
			// evt.Id = state.IKE_REKEY
			// o.fsm.PostEvent(evt)
			case INFORMATIONAL:
				// handle in all states ?
				o.handleInformational(msg)
			}
		}
	}
	o.conn.Close()
	close(o.events)
	close(o.messages)
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
