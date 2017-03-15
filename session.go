package ike

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
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
	msgIDReq, msgIDResp uint32

	incoming chan *Message

	initIb, initRb  []byte
	responderCookie []byte // TODO - remove this from session

	*SessionData

	Logger log.Logger
}

// Housekeeping

func (o *Session) Tag() string {
	ini := "[I]"
	if !o.isInitiator {
		ini = "[R]"
	}
	return ini + o.IkeSpiI.String()
}

func (o *Session) String() string {
	return fmt.Sprintf("%s<=>%s %s", o.IkeSpiI, o.IkeSpiR, o.tkm)
}

func (o *Session) CreateIkeSa(nonce, dhPublic *big.Int, spiI, spiR []byte) error {
	if o.isInitiator {
		// peer responders nonce
		o.tkm.Nr = nonce
		// peer responders spi
		o.IkeSpiR = append([]byte{}, spiR...)
	} else {
		// peer initiators nonce
		o.tkm.Ni = nonce
		// peer initiators spi
		o.IkeSpiI = append([]byte{}, spiI...)
	}
	//
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// initialize dh shared with their public key
	err := o.tkm.DhGenerateKey(dhPublic)
	if err != nil {
		return err
	}
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	o.Logger.Log("IKE_SA", "initialised", "session", o)
	return nil
}

func (o *Session) SetCookie(cn *protocol.NotifyPayload) {
	o.responderCookie = cn.NotificationMessage.([]byte)
}

func (o *Session) PostMessage(m *Message) {
	if err := o.isMessageValid(m); err != nil {
		level.Error(o.Logger).Log("Drop", err)
		return
	}
	if err := DecryptMessage(m, o.tkm, o.isInitiator, o.Logger); err != nil {
		level.Warn(o.Logger).Log("Drop", err)
		return
	}
	if o.isClosing {
		level.Error(o.Logger).Log("Drop", "Closing")
		return
	}
	o.incoming <- m
}

func (o *Session) encode(msg *Message) (*OutgoingMessge, error) {
	buf, err := msg.Encode(o.tkm, o.isInitiator, o.Logger)
	return &OutgoingMessge{buf}, err
}

func (o *Session) sendMsg(msg *OutgoingMessge, err error) error {
	if err != nil {
		return err
	}
	return WriteData(o.Conn, msg.Data, o.Remote, o.Logger)
}

// nextMsgID increments and returns response ids for responses, returns request ids as is
func (o *Session) nextMsgID(isResponse bool) (msgID uint32) {
	if isResponse {
		msgID = o.msgIDResp
		o.msgIDResp++
	} else {
		msgID = o.msgIDReq
	}
	return
}

// Close is called to shutdown this session
func (o *Session) Close(err error) {
	o.Logger.Log("msg", "Close Session", "err", err)
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
	return initMsg(o.nextMsgID(!o.isInitiator)) // is a response if not an initiator
}

// AuthMsg generates IKE_AUTH
func (o *Session) AuthMsg() (*OutgoingMessge, error) {
	o.Logger.Log("msg", "AUTH", "selectors", fmt.Sprintf("[INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR))
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth, err := AuthFromSession(o)
	if !o.isInitiator {
		o.IkeAuth(err)
	}
	if err != nil {
		o.Logger.Log("err", err)
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth.IkeHeader.MsgId = o.nextMsgID(!o.isInitiator) // is a response if not an initiator
	return o.encode(auth)
}

func (o *Session) RekeyMsg(child *Message) (*OutgoingMessge, error) {
	child.IkeHeader.MsgId = o.nextMsgID(!o.isInitiator) // is a response if not an initiator
	// encode & send
	return o.encode(child)
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

// InstallSa - adds a child SA
func (o *Session) InstallSa() error {
	return o.AddSa(addSaParams(o.tkm,
		o.tkm.Ni, o.tkm.Nr, nil, // NOTE : we use the original SA
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator))
}

// UnInstallSa removes the child SA
func (o *Session) UnInstallSa() {
	o.RemoveSa(removeSaParams(
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator))
}

// HandleClose will cleanly removes child SAs upon receiving a message from peer
func (o *Session) HandleClose() error {
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
	info.IkeHeader.MsgId = o.nextMsgID(false) // never a response
	// encode & send
	o.sendMsg(o.encode(info))
}

func (o *Session) sendIkeSaDelete() {
	info := DeleteFromSession(o)
	info.IkeHeader.MsgId = o.nextMsgID(false) // never a response
	// encode & send
	o.sendMsg(o.encode(info))
}

// SendEmptyInformational can be used for periodic keepalive
func (o *Session) SendEmptyInformational(isResponse bool) error {
	info := EmptyFromSession(o, isResponse)
	info.IkeHeader.MsgId = o.nextMsgID(isResponse)
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
		if seq != o.msgIDReq {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected response id %d, expected %d", seq, o.msgIDReq))
		}
		// requestId has been confirmed, increment it for next request
		o.msgIDReq++
	} else { // request
		// TODO - does not handle our responses getting lost
		if seq != o.msgIDResp {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected request id %d, expected %d", seq, o.msgIDResp))
		}
		// incremented by sender
	}
	return nil
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

func (o *Session) IkeAuth(err error) {
	if err == nil {
		o.Logger.Log("IKE_SA", "installed", "sa", o)
	} else {
		level.Warn(o.Logger).Log("IKE_SA", "failed", "err", err)
	}
}
func (o *Session) AddSa(sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.AddSa(o, sa)
	o.Logger.Log("CHILD_SA", "installed",
		"sa", fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res),
		"err", err)
	return err
}
func (o *Session) RemoveSa(sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.RemoveSa(o, sa)
	o.Logger.Log("CHILD_SA", "removed",
		"sa", fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res),
		"err", err)
	return err
}
