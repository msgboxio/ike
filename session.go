package ike

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/pkg/errors"
)

type Session struct {
	context.Context
	cancel context.CancelFunc
	*state.Fsm
	isClosing bool

	cfg Config // copy of Config given to us

	tkm                   *Tkm
	authRemote, authLocal Authenticator

	isInitiator         bool
	IkeSpiI, IkeSpiR    protocol.Spi
	EspSpiI, EspSpiR    protocol.Spi
	msgIdReq, msgIdResp uint32

	incoming chan *Message

	initIb, initRb  []byte
	responderCookie []byte // TODO - remove this from session

	Logger *logrus.Logger
}

// Housekeeping

func (o *Session) Tag() string {
	ini := "[I]"
	if !o.isInitiator {
		ini = "[R]"
	}
	return fmt.Sprintf(ini+"%#x", o.IkeSpiI)
}

func (o *Session) SetCookie(cn *protocol.NotifyPayload) {
	o.responderCookie = cn.NotificationMessage.([]byte)
}

func (o *Session) Run() {
	for {
		select {
		case msg, ok := <-o.incoming:
			if !ok {
				break
			}
			if err := o.handleEncryptedMessage(msg); err != nil {
				o.Logger.Warningf("Drop message: %s", err)
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
			o.Logger.Infof("Finished IKE session")
			return
		}
	}
}

func (o *Session) PostMessage(m *Message) {
	if err := o.isMessageValid(m); err != nil {
		o.Logger.Error("Drop Message: ", err)
		return
	}
	if o.Context.Err() != nil {
		o.Logger.Error("Drop Message: Closing")
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

func incomingAddress(incoming interface{}) net.Addr {
	msg, ok := incoming.(*Message)
	if !ok {
		return nil
	}
	return msg.RemoteAddr
}

func (o *Session) encode(msg *Message, to net.Addr) (*OutgoingMessge, error) {
	buf, err := msg.Encode(o.tkm, o.isInitiator, o.Logger)
	if err != nil {
		return nil, err
	}
	return &OutgoingMessge{buf, to}, nil
}

func (o *Session) sendMsg(msg *OutgoingMessge, err error) (s *state.StateEvent) {
	if err != nil {
		goto fail
	}
	err = ContextCallback(o).SendMessage(o, msg)
fail:
	if err != nil {
		o.Logger.Error(err)
		return &state.StateEvent{
			Event: state.FAIL,
			Error: err,
		}
	}
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
	o.Logger.Infof("Close Session, err: %s", err)
	if o.isClosing {
		return
	}
	o.isClosing = true
	o.sendIkeSaDelete()
	// TODO - start timeout to delete sa if peers does not reply
	o.PostEvent(&state.StateEvent{Event: state.DELETE_IKE_SA, Error: err})
}

// actions from FSM

// Finished is called by state machine upon entering finished state
func (o *Session) Finished(*state.StateEvent) (s *state.StateEvent) {
	close(o.incoming)
	o.CloseFsm()
	o.Logger.Infof("Finished; cancel context")
	o.cancel(context.Canceled)
	return
}

// SendInit callback from state machine
func (o *Session) SendInit(inEvt *state.StateEvent) (s *state.StateEvent) {
	initMsg := func(msgId uint32) (*OutgoingMessge, error) {
		init := InitFromSession(o)
		init.IkeHeader.MsgId = msgId
		// encode
		initB, err := o.encode(init, incomingAddress(inEvt.Message))
		if err != nil {
			return nil, err
		}
		if o.isInitiator {
			o.initIb = initB.Data
		} else {
			o.initRb = initB.Data
		}
		return initB, nil
	}
	return o.sendMsg(initMsg(o.msgIdInc(!o.isInitiator)))
}

// SendAuth callback from state machine
func (o *Session) SendAuth(inEvt *state.StateEvent) (s *state.StateEvent) {
	o.Logger.Infof("SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	auth, err := AuthFromSession(o)
	if err != nil {
		o.Logger.Infof("Error Authenticating: %+v", err)
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	auth.IkeHeader.MsgId = o.msgIdInc(!o.isInitiator)
	return o.sendMsg(o.encode(auth, incomingAddress(inEvt.Message)))
}

// InstallSa callback from state machine
func (o *Session) InstallSa(*state.StateEvent) (s *state.StateEvent) {
	sa := addSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator)
	ContextCallback(o).AddSa(o, sa)
	// move to STATE_MATURE state
	o.PostEvent(&state.StateEvent{Event: state.SUCCESS})
	return
}

// RemoveSa callback from state machine
func (o *Session) RemoveSa(*state.StateEvent) (s *state.StateEvent) {
	sa := removeSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator)
	ContextCallback(o).RemoveSa(o, sa)
	return
}

// handlers

// HandleIkeSaInit callback from state machine
func (o *Session) HandleIkeSaInit(evt *state.StateEvent) (s *state.StateEvent) {
	// response
	m := evt.Message.(*Message)
	if err := HandleInitForSession(o, m); err != nil {
		o.Logger.Infof("Error Initializing: %+v", err)
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
	params, err := parseAuth(m)
	if o.Logger.Level == logrus.DebugLevel {
		o.Logger.Debugf("params: \n%s; err %+v", spew.Sdump(params), err)
	}
	if err != nil {
		goto onError
	}
	if err = HandleAuthForSession(o, m); err != nil {
		goto onError
	}
	if err = o.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		goto onError
	}
	// TODO - check selectors
	o.Logger.Infof("Configured selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
	o.Logger.Infof("Offered selectors: [INI]%s<=>%s[RES]", params.tsI, params.tsR)
	// message looks OK
	if o.isInitiator {
		if params.isResponse {
			o.EspSpiR = append([]byte{}, params.spiR...)
		}
		if o.EspSpiR == nil {
			err = errors.New("Missing responder SPI")
		}
	} else {
		if !params.isResponse {
			o.EspSpiI = append([]byte{}, params.spiI...)
		}
		if o.EspSpiI == nil {
			err = errors.New("Missing initiator SPI")
		}
	}
	if err != nil {
		goto onError
	}
	// start Lifetime timer
	if params.lifetime != 0 {
		reauth := params.lifetime - 2*time.Second
		if params.lifetime <= 2*time.Second {
			reauth = 0
		}
		o.Logger.Infof("Lifetime: %s; reauth in %s", params.lifetime, reauth)
		time.AfterFunc(reauth, func() {
			o.Logger.Info("Lifetime Expired")
			o.PostEvent(&state.StateEvent{Event: state.REKEY_START})
		})
	}
	// transport mode
	if params.isTransportMode && o.cfg.IsTransportMode {
		o.Logger.Info("Using Transport Mode")
	} else {
		if params.isTransportMode {
			o.Logger.Info("Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			err = errors.New("Peer Rejected Transport Mode Config")
			goto onError
		}
	}
	// inform user
	ContextCallback(o).IkeAuth(o, err)
onError:
	if err != nil {
		return &state.StateEvent{
			Event: state.AUTH_FAIL,
			Error: err,
		}
	}
	return
}

// CheckSa callback from state machine
func (o *Session) CheckSa(evt *state.StateEvent) (s *state.StateEvent) {
	return
}

func (o *Session) HandleClose(evt *state.StateEvent) (s *state.StateEvent) {
	o.Logger.Infof("Peer Closed Session")
	if o.isClosing {
		return
	}
	o.isClosing = true
	o.SendEmptyInformational(true)
	o.RemoveSa(evt)
	return
}

func (o *Session) HandleCreateChildSa(evt *state.StateEvent) (s *state.StateEvent) {
	m := evt.Message.(*Message)
	if err := HandleSaRekey(o, m); err != nil {
		o.Logger.Info("Rekey Error: %+v", err)
	}
	// do we need to send NO_ADDITIONAL_SAS ?
	// ask user to create new SA
	ContextCallback(o).RekeySa(o)
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
	o.sendMsg(o.encode(info, nil))
}

func (o *Session) sendIkeSaDelete() {
	info := DeleteFromSession(o)
	info.IkeHeader.MsgId = o.msgIdInc(false)
	// encode & send
	o.sendMsg(o.encode(info, nil))
}

// SendEmptyInformational can be used for periodic keepalive
func (o *Session) SendEmptyInformational(isResponse bool) {
	info := EmptyFromSession(o, isResponse)
	info.IkeHeader.MsgId = o.msgIdInc(isResponse)
	// encode & send
	o.sendMsg(o.encode(info, nil))
}

func (o *Session) AddHostBasedSelectors(local, remote net.IP) error {
	slen := len(local) * 8
	ini := remote
	res := local
	if o.isInitiator {
		ini = local
		res = remote
	}
	return o.cfg.AddSelector(
		&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
		&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
}

func (o *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return errors.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		// TODO - remove IDLE
		if o.Fsm.State != state.STATE_IDLE && o.Fsm.State != state.STATE_START {
			return errors.Errorf("unexpected unencrypted message in state: %s", o.Fsm.State)
		}
	}
	// check sequence numbers
	seq := m.IkeHeader.MsgId
	if m.IkeHeader.Flags.IsResponse() {
		// response id ought to be the same as our request id
		if seq != o.msgIdReq {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected response id %d, expected %d", seq, o.msgIdReq))
		}
		// requestId has been confirmed, increment it for next request
		o.msgIdReq++
	} else { // request
		// TODO - does not handle our responses getting lost
		if seq != o.msgIdResp {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected request id %d, expected %d", seq, o.msgIdResp))
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
		if err = m.DecodePayloads(b, sk.NextPayloadType(), o.Logger); err != nil {
			return err
		}
	}
	return
}
