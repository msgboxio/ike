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

type ClientCallback func(interface{}) error

type SaMessage struct {
	*platform.SaParams
	IsAdd bool
}

type Session struct {
	context.Context
	cancel context.CancelFunc
	*state.Fsm
	isClosing bool

	cfg *Config // copy of Config given to us

	tkm                   *Tkm
	authRemote, authLocal Authenticator
	// should we use rfc7427 signature algos?
	rfc7427Signatures bool

	isInitiator         bool
	IkeSpiI, IkeSpiR    protocol.Spi
	EspSpiI, EspSpiR    protocol.Spi
	msgIdReq, msgIdResp uint32

	incoming chan *Message
	outgoing chan []byte

	initIb, initRb []byte
	initCookie     []byte // TODO - remove this from sesion

	callback ClientCallback
}

// Housekeeping

func (o *Session) Tag() string {
	return fmt.Sprintf("%#x<=>%#x: ", o.IkeSpiI, o.IkeSpiR)
}

func (o *Session) SetCookie(cn *protocol.NotifyPayload) {
	o.initCookie = cn.NotificationMessage.([]byte)
}

func (o *Session) SetCbHandler(cb ClientCallback) {
	o.callback = cb
}

func (o *Session) Run() {
	for {
		select {
		case reply, ok := <-o.outgoing:
			if !ok {
				break
			}
			if err := o.callback(reply); err != nil {
				o.Close(err)
				break
			}
		case msg, ok := <-o.incoming:
			if !ok {
				break
			}
			if err := o.handleEncryptedMessage(msg); err != nil {
				log.Warningf(o.Tag()+"Drop message: %s", err)
				break
			}
			if evt := o.handleMessage(msg); evt != nil {
				o.PostEvent(evt)
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
	evt = &state.StateEvent{Message: msg}
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

func (o *Session) sendMsg(buf []byte, err error) (s *state.StateEvent) {
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Error = err
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
	o.PostEvent(&state.StateEvent{Event: state.DELETE_IKE_SA, Error: err})
}

// SetHashAlgorithms callback from ike sa init
func (o *Session) SetHashAlgorithms(isEnabled bool) {
	if !isEnabled && o.rfc7427Signatures {
		log.Warningln("Peer is not using secure signatures")
	}
	o.rfc7427Signatures = isEnabled
}

// actions from FSM

// Finished is called by state machine upon entering finished state
func (o *Session) Finished(*state.StateEvent) (s *state.StateEvent) {
	if queued := len(o.outgoing); queued > 0 {
		// drain queue by going round the block again
		o.PostEvent(&state.StateEvent{Event: state.FINISHED})
		return
	}
	close(o.incoming)
	close(o.outgoing)
	o.CloseEvents()
	log.Info(o.Tag() + "Finished; cancel context")
	o.cancel(context.Canceled)
	return
}

// SendInit callback from state machine
func (o *Session) SendInit(*state.StateEvent) (s *state.StateEvent) {
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
func (o *Session) SendAuth(*state.StateEvent) (s *state.StateEvent) {
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	log.V(1).Infof(o.Tag()+"SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
	auth := AuthFromSession(o)
	if auth == nil {
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	auth.IkeHeader.MsgId = o.msgIdInc(!o.isInitiator)
	return o.sendMsg(auth.Encode(o.tkm, o.isInitiator))
}

// InstallSa callback from state machine
func (o *Session) InstallSa(*state.StateEvent) (s *state.StateEvent) {
	sa := addSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.isInitiator)
	o.callback(&SaMessage{sa, true})
	// move to STATE_MATURE state
	o.PostEvent(&state.StateEvent{Event: state.SUCCESS})
	return
}

// RemoveSa callback from state machine
func (o *Session) RemoveSa(*state.StateEvent) (s *state.StateEvent) {
	sa := removeSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.isInitiator)
	o.callback(&SaMessage{sa, false})
	return
}

// handlers

// HandleIkeSaInit callback from state machine
func (o *Session) HandleIkeSaInit(evt *state.StateEvent) (s *state.StateEvent) {
	// response
	m := evt.Message.(*Message)
	if err := HandleInitForSession(o, m); err != nil {
		log.Error(err)
		return &state.StateEvent{
			Event: state.INIT_FAIL,
			Error: protocol.ERR_NO_PROPOSAL_CHOSEN, // TODO - always return this?
		}
	}
	return
}

// HandleIkeAuth callback from state machine
func (o *Session) HandleIkeAuth(evt *state.StateEvent) (s *state.StateEvent) {
	// response
	m := evt.Message.(*Message)
	if err := HandleAuthForSession(o, m); err != nil {
		log.Error(err)
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: err,
		}
	}
	return
}

// CheckSa callback from state machine
func (o *Session) CheckSa(evt *state.StateEvent) (s *state.StateEvent) {
	// get message
	msg := evt.Message.(*Message)
	return checkSaForSession(o, msg)
}

func (o *Session) HandleClose(evt *state.StateEvent) (s *state.StateEvent) {
	log.Infof(o.Tag() + "Peer Closed Session")
	if o.isClosing {
		return
	}
	o.isClosing = true
	o.SendEmptyInformational(true)
	o.RemoveSa(evt)
	return
}

func (o *Session) HandleCreateChildSa(evt *state.StateEvent) (s *state.StateEvent) {
	s.Event = state.AUTH_FAIL
	m := evt.Message.(*Message)
	if err := m.EnsurePayloads(InitPayloads); err == nil {
		log.Infof(o.Tag() + "peer requests IKE rekey")
	} else {
		log.Infof(o.Tag() + "peer requests IPSEC rekey")
	}
	s.Error = protocol.ERR_NO_ADDITIONAL_SAS
	return
}

// CheckError callback from fsm
// if there is a notification, then log and ignore
// if there is an error, then send to peer
func (o *Session) CheckError(evt *state.StateEvent) (s *state.StateEvent) {
	if iErr, ok := evt.Error.(protocol.IkeErrorCode); ok {
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

func (o *Session) AddHostBasedSelectors(local, remote net.IP) {
	log.Infoln(o.Tag() + "Adding host based traffic selectors")
	slen := len(local) * 8
	ini := remote
	res := local
	if o.isInitiator {
		ini = local
		res = remote
	}
	o.cfg.AddSelector(
		&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
		&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
}

func (o *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return fmt.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		// TODO - remove IDLE
		if o.Fsm.State != state.STATE_IDLE && o.Fsm.State != state.STATE_START {
			return fmt.Errorf("unexpected unencrypted message in state: %s", o.Fsm.State)
		}
	}
	// check sequence numbers
	seq := m.IkeHeader.MsgId
	if m.IkeHeader.Flags.IsResponse() {
		// response id ought to be the same as our request id
		if seq != o.msgIdReq {
			return protocol.ErrF(protocol.ERR_INVALID_MESSAGE_ID, "unexpected response id %d, expected %d",
				seq, o.msgIdReq)
		}
		// requestId has been confirmed, increment it for next request
		o.msgIdReq++
	} else { // request
		// TODO - does not handle our responses getting lost
		if seq != o.msgIdResp {
			return protocol.ErrF(protocol.ERR_INVALID_MESSAGE_ID, "unexpected request id %d, expected %d",
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
