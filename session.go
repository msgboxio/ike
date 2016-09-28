package ike

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

type SaCallback func(sa *platform.SaParams) error
type WriteData func([]byte) error

// Session is closed by us:
// > call close(): returns if closing already
// > otherwise sets closing; send N[D] Req
// > posts event
// >> fsm calls RemoveSa
// >>> removes SA
// >>> calls Close()
// 2> We wait for N[D], then remove SA
// 3> move to finished
// When receive N[D]
// > fsm calls RemoveSa
// >> removes SA
// >> calls Close
// > call Close() which sends N[D]
// > move to finished
type Session struct {
	context.Context
	cancel context.CancelFunc
	*state.Fsm
	isInitiator bool

	isClosing bool

	tkm *Tkm
	cfg *Config

	authRemote, authLocal Authenticator
	remote, local         net.Addr

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	incoming chan *Message
	outgoing chan []byte

	msgIdReq, msgIdResp uint32

	// should we use rfc7427 signature algos?
	rfc7427Signatures bool

	initIb, initRb []byte

	onAddSaCallback, onRemoveSaCallback SaCallback
}

// Housekeeping

var _tag string

func (o *Session) Tag() string {
	if _tag != "" {
		return _tag
	}
	ini := o.local
	res := o.remote
	if !o.isInitiator {
		ini = o.remote
		res = o.local
	}
	_tag = fmt.Sprintf("[%s]%#x<=>%#x[%s]: ",
		ini,
		o.IkeSpiI,
		o.IkeSpiR,
		res)
	return _tag
}

func (o *Session) Run(writeData WriteData, onAddSa, onRemoveSa SaCallback) {
	o.onAddSaCallback = onAddSa
	o.onRemoveSaCallback = onRemoveSa
	for {
		select {
		case reply, ok := <-o.outgoing:
			if !ok {
				break
			}
			if err := writeData(reply); err != nil {
				o.Close(err)
				break
			}
		case msg, ok := <-o.incoming:
			if !ok {
				break
			}
			if err := o.handleEncryptedMessage(msg); err != nil {
				log.Warning(err)
				break
			}
			if evt := o.handleMessage(msg); evt != nil {
				o.PostEvent(*evt)
			}
		case evt, ok := <-o.Events():
			if !ok {
				break
			}
			o.HandleEvent(evt)
		case <-o.Done():
			log.Info(o.Tag() + "Finished IKE SA")
			return
		}
	}
}

// Close is called to shutdown this session
func (o *Session) Close(err error) {
	log.Infof(o.Tag()+"Close Session, err %s", err)
	if o.isClosing {
		return
	}
	o.isClosing = true
	// send to peer, peer should send SA_DELETE message
	o.sendIkeSaDelete(err)
	// TODO - start timeout to delete sa if peers does not reply
	// o.PostEvent(state.StateEvent{Event: state.DELETE_IKE_SA, Data: err})
}

func (o *Session) PostMessage(m *Message) {
	if err := o.isMessageValid(m); err != nil {
		log.Error(o.Tag()+"Drop Message: ", err)
		return
	}
	if o.Context.Err() != nil {
		log.Error(o.Tag() + "Drop Message: Closing")
		return
	}
	o.incoming <- m
}

func (o *Session) handleMessage(msg *Message) (evt *state.StateEvent) {
	evt = &state.StateEvent{Data: msg}
	switch msg.IkeHeader.ExchangeType {
	case protocol.IKE_SA_INIT:
		evt.Event = state.MSG_INIT
		return
	case protocol.IKE_AUTH:
		evt.Event = state.MSG_AUTH
		return
	case protocol.CREATE_CHILD_SA:
		evt.Event = state.MSG_CHILD_SA
		return
	case protocol.INFORMATIONAL:
		// Notification, Delete, and Configuration Payloads
		if del := msg.Payloads.Get(protocol.PayloadTypeD); del != nil {
			dp := del.(*protocol.DeletePayload)
			if dp.ProtocolId == protocol.IKE {
				log.Infof(o.Tag()+"Peer remove IKE SA : %#x", msg.IkeHeader.SpiI)
				evt.Event = state.MSG_DELETE_IKE_SA
				return
			}
			for _, spi := range dp.Spis {
				if dp.ProtocolId == protocol.ESP {
					log.Infof(o.Tag()+"Peer remove ESP SA : %#x", spi)
					// TODO
				}
			}
		} // del
		// delete the ike sa if notification is one of following
		// UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, an AUTHENTICATION_FAILED
		if note := msg.Payloads.Get(protocol.PayloadTypeN); note != nil {
			np := note.(*protocol.NotifyPayload)
			if err, ok := protocol.GetIkeErrorCode(np.NotificationType); ok {
				log.Errorf(o.Tag()+"Received Error: %v", err)
				evt.Event = state.FAIL
				evt.Data = np.NotificationType
				return
			}
		}
	}
	return nil
}

func (o *Session) sendMsg(buf []byte, err error) (s state.StateEvent) {
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- buf
	return
}

// callbacks

// SetHashAlgorithms callback from ike sa init
func (o *Session) SetHashAlgorithms(isEnabled bool) {
	if !isEnabled && o.rfc7427Signatures {
		log.Warningln("Peer is not using secure signatures")
	}
	o.rfc7427Signatures = isEnabled
}

// SendInit callback from state machine
func (o *Session) SendInit() (s state.StateEvent) {
	initMsg := func(msgId uint32) ([]byte, error) {
		init := InitFromSession(o)
		init.IkeHeader.MsgId = msgId
		// encode
		initB, err := init.Encode(o.tkm, o.isInitiator)
		if err != nil {
			return nil, err
		}
		if o.isInitiator {
			o.initIb = initB
		} else {
			o.initRb = initB
		}
		return initB, nil
	}
	var msgId uint32
	if o.isInitiator {
		msgId = o.msgIdReq
		o.msgIdReq++
	} else {
		msgId = o.msgIdResp
		o.msgIdResp++
	}
	return o.sendMsg(initMsg(msgId))
}

// SendAuth callback from state machine
func (o *Session) SendAuth() (s state.StateEvent) {
	auth := AuthFromSession(o)
	if auth == nil {
		return state.StateEvent{
			Event: state.AUTH_FAIL,
			Data:  protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	var msgId uint32
	if o.isInitiator {
		msgId = o.msgIdReq
		o.msgIdReq++
	} else {
		msgId = o.msgIdResp
		o.msgIdResp++
	}
	auth.IkeHeader.MsgId = msgId
	return o.sendMsg(auth.Encode(o.tkm, o.isInitiator))
}

func (o *Session) InstallSa() (s state.StateEvent) {
	sa := addSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.local, o.remote,
		o.isInitiator)
	if o.onAddSaCallback != nil {
		o.onAddSaCallback(sa)
	}
	return
}

func (o *Session) RemoveSa() (s state.StateEvent) {
	sa := removeSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.local, o.remote,
		o.isInitiator)
	if o.onRemoveSaCallback != nil {
		o.onRemoveSaCallback(sa)
	}
	o.Close(PeerDeletedSa)
	return
}

func (o *Session) StartRetryTimeout() (s state.StateEvent) {
	return
}

// Finished is called by state machine upon entering finished state
func (o *Session) Finished() (s state.StateEvent) {
	if queued := len(o.outgoing); queued > 0 {
		// drain queue by going round the block again
		o.PostEvent(state.StateEvent{Event: state.FINISHED})
		return
	}
	close(o.incoming)
	close(o.outgoing)
	o.CloseEvents()
	log.Info(o.Tag() + "Finished; cancel context")
	o.cancel(context.Canceled)
	return
}

// handlers

// HandleIkeSaInit callback from state machine
func (o *Session) HandleIkeSaInit(msg interface{}) state.StateEvent {
	// response
	m := msg.(*Message)
	if err := HandleInitForSession(o, m); err != nil {
		log.Error(err)
		return state.StateEvent{
			Event: state.INIT_FAIL,
			Data:  protocol.ERR_NO_PROPOSAL_CHOSEN, // TODO - always return this?
		}
	}
	return state.StateEvent{Event: state.SUCCESS}
}

// HandleIkeAuth callback from state machine
func (o *Session) HandleIkeAuth(msg interface{}) (s state.StateEvent) {
	// response
	m := msg.(*Message)
	if err := HandleAuthForSession(o, m); err != nil {
		log.Error(err)
		return state.StateEvent{Event: state.AUTH_FAIL, Data: err}
	}
	// move to STATE_MATURE state
	o.PostEvent(state.StateEvent{Event: state.SUCCESS, Data: m})
	return state.StateEvent{Event: state.SUCCESS}
}

// CheckSa callback from state machine
func (o *Session) CheckSa(m interface{}) (s state.StateEvent) {
	// get message
	msg := m.(*Message)
	// get peer spi
	espSpi, err := getPeerSpi(msg, protocol.ESP)
	if err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	if o.isInitiator {
		o.EspSpiR = append([]byte{}, espSpi...)
	} else {
		o.EspSpiI = append([]byte{}, espSpi...)
	}
	// check transport mode, and other info payloads
	wantsTransportMode := false
	for _, ns := range msg.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.AUTH_LIFETIME:
			lft := ns.NotificationMessage.(time.Duration)
			reauth := lft - 2*time.Second
			if lft <= 2*time.Second {
				reauth = 0
			}
			log.Infof(o.Tag()+"Lifetime: %s; reauth in %s", lft, reauth)
			time.AfterFunc(reauth, func() {
				o.PostEvent(state.StateEvent{Event: state.REKEY_START})
			})
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	if wantsTransportMode && o.cfg.IsTransportMode {
		log.Info(o.Tag() + "Using Transport Mode")
	} else {
		if wantsTransportMode {
			log.Info(o.Tag() + "Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			err := errors.New("Peer Rejected Transport Mode Config")
			log.Error(o.Tag() + err.Error())
			s.Data = err
		}
	}
	// load additional configs
	if err := o.cfg.AddFromAuth(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - check IPSEC selectors & config
	s.Event = state.SUCCESS
	return
}

func (o *Session) HandleCreateChildSa(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	m := msg.(*Message)
	if err := m.EnsurePayloads(InitPayloads); err == nil {
		log.Infof(o.Tag() + "peer requests IKE rekey")
	} else {
		log.Infof(o.Tag() + "peer requests IPSEC rekey")
	}
	s.Data = protocol.ERR_NO_ADDITIONAL_SAS
	return
}

// CheckError callback from fsm
// if there is a notification, then log and ignore
// if there is an error, then send to peer
func (o *Session) CheckError(msg interface{}) (s state.StateEvent) {
	if notif, ok := msg.(protocol.NotificationType); ok {
		// check if the received notification was an error
		if _, ok := protocol.GetIkeErrorCode(notif); ok {
			// ignore it
			return
		}
	} else if iErr, ok := msg.(protocol.IkeErrorCode); ok {
		o.Notify(iErr)
		return
	}
	return
}

// utilities

func (o *Session) Notify(ie protocol.IkeErrorCode) {
	spi := o.IkeSpiI
	if o.isInitiator {
		spi = o.IkeSpiR
	}
	// INFORMATIONAL
	info := MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
		Payload: &protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			ProtocolId:       protocol.IKE,
			NotificationType: protocol.NotificationType(ie),
			Spi:              spi,
		},
	})
	var msgId uint32
	if o.isInitiator {
		msgId = o.msgIdReq
		o.msgIdReq++
	} else {
		msgId = o.msgIdResp
		o.msgIdResp++
	}
	info.IkeHeader.MsgId = msgId
	// encode & send
	o.sendMsg(info.Encode(o.tkm, o.isInitiator))
}

func (o *Session) sendIkeSaDelete(err error) {
	var msgId uint32
	var isResponse bool
	if err == PeerDeletedSa {
		// received delete from peer, so reply
		isResponse = true
		msgId = o.msgIdResp
		o.msgIdResp++
	} else {
		// sending delete to peer
		msgId = o.msgIdReq
		o.msgIdReq++
	}
	// ike protocol ID, but no spi
	info := MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		IsResponse:  isResponse,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
		Payload: &protocol.DeletePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			ProtocolId:    protocol.IKE,
			Spis:          []protocol.Spi{},
		},
	})
	info.IkeHeader.MsgId = msgId
	// encode & send
	o.sendMsg(info.Encode(o.tkm, o.isInitiator))
}

// SendEmptyInformational can be used for periodic keepalive
func (o *Session) SendEmptyInformational() {
	// INFORMATIONAL
	info := MakeInformational(InfoParams{
		IsInitiator: o.isInitiator,
		SpiI:        o.IkeSpiI,
		SpiR:        o.IkeSpiR,
	})
	var msgId uint32
	if o.isInitiator {
		msgId = o.msgIdReq
		o.msgIdReq++
	} else {
		msgId = o.msgIdResp
		o.msgIdResp++
	}
	info.IkeHeader.MsgId = msgId
	// encode & send
	o.sendMsg(info.Encode(o.tkm, o.isInitiator))
}

func (o *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return fmt.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	if !AddrToIp(o.remote).Equal(AddrToIp(m.RemoteAddr)) {
		return fmt.Errorf("different remote IP %v vs %v", o.remote, m.RemoteAddr)
	}
	// local IP is not set initially for initiator
	if o.local == nil {
		o.local = m.LocalAddr
	} else if !AddrToIp(o.local).Equal(AddrToIp(m.LocalAddr)) {
		return fmt.Errorf("different local IP %v vs %v", o.local, m.LocalAddr)
	}
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		if o.Fsm.State != state.STATE_IDLE && o.Fsm.State != state.STATE_START {
			return fmt.Errorf("unexpected unencrypted message in state: %s", o.Fsm.State)
		}
	}
	return nil
}

func (o *Session) handleEncryptedMessage(m *Message) (err error) {
	if m.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		var b []byte
		if b, err = o.tkm.VerifyDecrypt(m.Data, o.isInitiator); err != nil {
			return err
		}
		sk := m.Payloads.Get(protocol.PayloadTypeSK)
		if err = m.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return err
		}
	}
	return
}
