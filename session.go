package ike

import (
	"bytes"
	"fmt"
	"net"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

type SaCallback func(sa *platform.SaParams) error
type WriteData func([]byte) error

type Session struct {
	context.Context
	cancel context.CancelFunc
	*state.Fsm
	isClosing bool

	cfg *Config

	tkm                   *Tkm
	authRemote, authLocal Authenticator
	// should we use rfc7427 signature algos?
	rfc7427Signatures bool

	remote, local net.Addr

	isInitiator         bool
	IkeSpiI, IkeSpiR    protocol.Spi
	EspSpiI, EspSpiR    protocol.Spi
	msgIdReq, msgIdResp uint32

	incoming chan *Message
	outgoing chan []byte

	initIb, initRb []byte

	onAddSaCallback, onRemoveSaCallback SaCallback
}

// Housekeeping

func (o *Session) Tag() string {
	ini := o.local
	res := o.remote
	if !o.isInitiator {
		ini = o.remote
		res = o.local
	}
	tag := fmt.Sprintf("[%s]%#x<=>%#x[%s]: ",
		ini,
		o.IkeSpiI,
		o.IkeSpiR,
		res)
	return tag
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
		return HandleInformationalForSession(o, msg)
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

func (o *Session) msgIdInc(isResponse bool) (msgId uint32) {
	if isResponse {
		msgId = o.msgIdResp
		o.msgIdResp++
	} else {
		msgId = o.msgIdReq
	}
	return
}

// Close is called to shutdown this session
func (o *Session) Close(err error) {
	log.Infof(o.Tag()+"Close Session, err: %s", err)
	if o.isClosing {
		return
	}
	o.isClosing = true
	o.sendIkeSaDelete()
	// TODO - start timeout to delete sa if peers does not reply
	o.PostEvent(state.StateEvent{Event: state.DELETE_IKE_SA, Data: err})
}

// callbacks

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
	return o.sendMsg(initMsg(o.msgIdInc(!o.isInitiator)))
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
	auth.IkeHeader.MsgId = o.msgIdInc(!o.isInitiator)
	return o.sendMsg(auth.Encode(o.tkm, o.isInitiator))
}

// InstallSa callback from state machine
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

// RemoveSa callback from state machine
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
	return
}

func (o *Session) StartRetryTimeout() (s state.StateEvent) {
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
	return checkSaForSession(o, msg)
}

func (o *Session) HandleClose(msg interface{}) (s state.StateEvent) {
	log.Infof(o.Tag() + "Peer Closed Session")
	if o.isClosing {
		return
	}
	o.isClosing = true
	o.SendEmptyInformational(true)
	o.RemoveSa()
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
	info := NotifyFromSession(o, ie)
	info.IkeHeader.MsgId = o.msgIdInc(false)
	// encode & send
	o.sendMsg(info.Encode(o.tkm, o.isInitiator))
}

func (o *Session) sendIkeSaDelete() {
	info := DeleteFromSession(o)
	info.IkeHeader.MsgId = o.msgIdInc(false)
	// encode & send
	o.sendMsg(info.Encode(o.tkm, o.isInitiator))
}

// SendEmptyInformational can be used for periodic keepalive
func (o *Session) SendEmptyInformational(isResponse bool) {
	info := EmptyFromSession(o, isResponse)
	info.IkeHeader.MsgId = o.msgIdInc(isResponse)
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
		// dont check
	} else if !AddrToIp(o.local).Equal(AddrToIp(m.LocalAddr)) {
		return fmt.Errorf("different local IP %v vs %v", o.local, m.LocalAddr)
	}
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		if o.Fsm.State != state.STATE_IDLE && o.Fsm.State != state.STATE_START {
			return fmt.Errorf("unexpected unencrypted message in state: %s", o.Fsm.State)
		}
	}
	// check sequence numbers
	seq := m.IkeHeader.MsgId
	if m.IkeHeader.Flags.IsResponse() {
		// response id ought to be the same as our request id
		if seq != o.msgIdReq {
			return fmt.Errorf("unexpected response id %d, expected %d",
				seq, o.msgIdReq)
		}
		// requestId has been confirmed, increment it for next request
		o.msgIdReq++
	} else { // request
		// TODO - does not handle our responses getting lost
		if seq != o.msgIdResp {
			return fmt.Errorf("unexpected request id %d, expected %d",
				seq, o.msgIdResp)
		}
		// incremented by sender
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
