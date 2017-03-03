package ike

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

const REPLY_WAIT_TIMEOUT = 5 * time.Second

type OutgoingMessge struct {
	Data []byte
}

type SessionCallback struct {
	AddSa    func(*Session, *platform.SaParams) error
	RemoveSa func(*Session, *platform.SaParams) error
}

type SessionData struct {
	Conn          Conn
	Local, Remote net.Addr
	Cb            SessionCallback
}

var ReplyTimedoutError error = replyTimeout{}

type replyTimeout struct{}

func (r replyTimeout) Error() string {
	return "Timed Out"
}

var SessionClosedError error = sessionClosed{}

type sessionClosed struct{}

func (s sessionClosed) Error() string {
	return "Session Closed"
}

func packetOrTimeOut(incoming <-chan *Message) (*Message, error) {
	select {
	case msg, ok := <-incoming:
		if ok {
			return msg, nil
		}
		return nil, SessionClosedError
	case <-time.After(Jitter(REPLY_WAIT_TIMEOUT, 0.2)):
		return nil, ReplyTimedoutError
	}
}

// Session stores IKE session's local state
type Session struct {
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

	*SessionData

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

func (o *Session) PostMessage(m *Message) {
	if err := o.isMessageValid(m); err != nil {
		o.Logger.Error("Drop Message: ", err)
		return
	}
	if err := o.handleEncryptedMessage(m); err != nil {
		o.Logger.Warningf("Drop message: %s", err)
		return
	}
	if o.isClosing {
		o.Logger.Error("Drop Message: Closing")
		return
	}
	o.incoming <- m
}

// case protocol.INFORMATIONAL:
// 	return HandleInformationalForSession(o, msg)
// }

func (o *Session) encode(msg *Message) (*OutgoingMessge, error) {
	buf, err := msg.Encode(o.tkm, o.isInitiator, o.Logger)
	if err != nil {
		return nil, err
	}
	return &OutgoingMessge{buf}, nil
}

func (o *Session) sendMsg(msg *OutgoingMessge, err error) error {
	if err != nil {
		return err
	}
	err = o.SendMessage(msg)
	if err != nil {
		o.Logger.Error(err)
	}
	return err
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
}

func (o *Session) InitMsg() (*OutgoingMessge, error) {
	initMsg := func(msgId uint32) (*OutgoingMessge, error) {
		init := InitFromSession(o)
		init.IkeHeader.MsgId = msgId
		// encode
		initB, err := o.encode(init)
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
	return initMsg(o.msgIdInc(!o.isInitiator))
}

// AuthMsg generates IKE_AUTH
func (o *Session) AuthMsg() (*OutgoingMessge, error) {
	o.Logger.Infof("SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth, err := AuthFromSession(o)
	if !o.isInitiator {
		o.IkeAuth(err)
	}
	if err != nil {
		o.Logger.Infof("Error Authenticating: %+v", err)
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth.IkeHeader.MsgId = o.msgIdInc(!o.isInitiator)
	return o.encode(auth)
}

// SendMsgGetReply takes a message generator
func (o *Session) SendMsgGetReply(genMsg func() (*OutgoingMessge, error)) (*Message, error) {
	for {
		// send initiator INIT after jittered wait
		if err := o.sendMsg(genMsg()); err != nil {
			return nil, err
		}
		// wait for reply, or timeout
		msg, err := packetOrTimeOut(o.incoming)
		if err != nil {
			// on timeout, send INIT again, and loop
			if err == ReplyTimedoutError {
				continue
			}
			return nil, err
		}
		return msg, err
	}
}

// SendAuth sends IKE_AUTH
func (o *Session) SendAuth() error {
	return o.sendMsg(o.AuthMsg())
}

// InstallSa - is used to create a new sa using the original IKE sa
func (o *Session) InstallSa() error {
	sa := addSa(o.tkm,
		o.tkm.Ni, o.tkm.Nr, nil, // NOTE : we use the original SA
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator)
	return o.AddSa(sa)
}

// UnInstallSa
func (o *Session) UnInstallSa() {
	sa := removeSa(
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator)
	o.RemoveSa(sa)
	return
}

// handlers

func (o *Session) HandleClose() error {
	o.Logger.Infof("Peer Closed Session")
	if o.isClosing {
		return nil
	}
	o.isClosing = true
	o.SendEmptyInformational(true)
	o.UnInstallSa()
	return nil
}

// CheckError
// if there is an error, then send to peer
func (o *Session) CheckError(err error) error {
	if iErr, ok := errors.Cause(err).(protocol.IkeErrorCode); ok {
		o.Notify(iErr)
		return nil
	}
	return err
}

// utilities

func (o *Session) Notify(ie protocol.IkeErrorCode) {
	info := NotifyFromSession(o, ie)
	info.IkeHeader.MsgId = o.msgIdInc(false)
	// encode & send
	o.sendMsg(o.encode(info))
}

func (o *Session) sendIkeSaDelete() {
	info := DeleteFromSession(o)
	info.IkeHeader.MsgId = o.msgIdInc(false)
	// encode & send
	o.sendMsg(o.encode(info))
}

// SendEmptyInformational can be used for periodic keepalive
func (o *Session) SendEmptyInformational(isResponse bool) error {
	info := EmptyFromSession(o, isResponse)
	info.IkeHeader.MsgId = o.msgIdInc(isResponse)
	// encode & send
	return o.sendMsg(o.encode(info))
}

func (o *Session) AddHostBasedSelectors(local, remote net.IP) error {
	slen := len(local) * 8
	ini := remote
	res := local
	if o.isInitiator {
		ini = local
		res = remote
	}
	err := o.cfg.AddSelector(
		&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
		&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
	if err != nil {
		return errors.Wrapf(err, "could not add selectors for %s=>%s", ini, res)
	}
	return nil
}

func (o *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return errors.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		// TODO -
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

func (c *Session) SetAddresses(local, remote net.Addr) {
	c.Local = local
	c.Remote = remote
}

func saAddr(sa *platform.SaParams, local, remote net.Addr) {
	remoteIP := AddrToIp(remote)
	localIP := AddrToIp(local)
	sa.Ini = remoteIP
	sa.Res = localIP
	if sa.IsInitiator {
		sa.Ini = localIP
		sa.Res = remoteIP
	}
}
func (o *Session) SendMessage(msg *OutgoingMessge) error {
	return o.Conn.WritePacket(msg.Data, o.Remote)
}
func (o *Session) IkeAuth(err error) {
	if err == nil {
		o.Logger.Info("New IKE SA: ", o)
	} else {
		o.Logger.Warningf("IKE SA FAILED: %+v", err)
	}
}
func (o *Session) AddSa(sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.AddSa(o, sa)
	o.Logger.Infof("Installed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
func (o *Session) RemoveSa(sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.RemoveSa(o, sa)
	o.Logger.Infof("Removed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
