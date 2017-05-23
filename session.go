package ike

import (
	"bytes"
	"context"
	stderror "errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var (
	errorReplyTimedout         = stderror.New("Timed Out")
	errorSessionClosed         = stderror.New("Session Closed")
	errorRekeyDeadlineExceeded = stderror.New("Rekey Deadline Exceeded")
	errPeerRemovedIkeSa        = stderror.New("Delete IKE SA")
	errPeerRemovedEspSa        = stderror.New("Delete ESP SA")
)

var sessionCount int32

// SessionCallback holds the callbacks used by the session to notify the user
type SessionCallback struct {
	InstallPolicy func(*Session, *protocol.PolicyParams) error
	RemovePolicy  func(*Session, *protocol.PolicyParams) error

	InstallChildSa func(*Session, *platform.SaParams) error
	RemoveChildSa  func(*Session, *platform.SaParams) error
}

// Session stores IKE session's local state
type Session struct {
	cxt       context.Context
	cancel    context.CancelFunc
	isClosing bool

	cfg Config // copy of Config given to us

	tkm                 *Tkm
	authPeer, authLocal Authenticator

	isInitiator       bool
	rfc7427Signatures bool
	SessionID         int32

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	msgIDReq, msgIDResp msgID

	incoming chan *Message

	// cached data
	initIb, initRb  []byte
	responderCookie []byte

	// data from client
	Conn          Conn
	Local, Remote net.Addr
	Cb            SessionCallback

	Logger log.Logger
}

// Constructors

// NewInitiator creates an initiator session
func NewInitiator(cfg *Config, remoteAddr net.Addr, conn Conn, cb *SessionCallback, logger log.Logger) (*Session, error) {
	tkm, err := NewTkm(cfg, nil)
	if err != nil {
		return nil, err
	}
	cxt, cancel := context.WithCancel(context.Background())
	sess := &Session{
		cxt:               cxt,
		cancel:            cancel,
		SessionID:         atomic.AddInt32(&sessionCount, 1),
		isInitiator:       true,
		rfc7427Signatures: true,
		tkm:               tkm,
		cfg:               *cfg,
		IkeSpiI:           MakeSpi(),
		incoming:          make(chan *Message, 10),
		Conn:              conn,
		Remote:            remoteAddr,
		Cb:                *cb,
		msgIDReq:          msgID{id: 0},
		msgIDResp:         msgID{id: -1},
	}
	sess.Logger = log.With(logger, "session", sess.tag())
	return sess, nil
}

// NewResponder creates a Responder session
func NewResponder(cfg *Config, conn Conn, cb *SessionCallback, initI *Message, logger log.Logger) (*Session, error) {
	// get spi
	ikeSpiI := initI.IkeHeader.SpiI
	// cast is safe since we already checked for presence of payloads
	// assert ?
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	// creating tkm is expensive, should come after checks are positive
	tkm, err := NewTkm(cfg, noI.Nonce)
	if err != nil {
		return nil, err
	}
	cxt, cancel := context.WithCancel(context.Background())
	// create and run session
	sess := &Session{
		cxt:       cxt,
		cancel:    cancel,
		SessionID: atomic.AddInt32(&sessionCount, 1),
		tkm:       tkm,
		cfg:       *cfg,
		IkeSpiI:   ikeSpiI,
		IkeSpiR:   MakeSpi(),
		incoming:  make(chan *Message, 10),
		Conn:      conn,
		Local:     initI.LocalAddr,
		Remote:    initI.RemoteAddr,
		Cb:        *cb,
		msgIDReq:  msgID{id: 0},
		msgIDResp: msgID{id: -1},
	}
	sess.Logger = log.With(logger, "session", sess.tag())
	return sess, nil
}

// Destructors

// Shutdown is called to initiate a session shutdown
// 1: peer shut us down, or 2: we are shutting down all sessions
func (sess *Session) Shutdown(err error) {
	sess.Logger.Log("Shutdown", err)
	if sess.isClosing {
		return
	}
	sess.isClosing = true
	// dont send Delete for
	switch errors.Cause(err) {
	case errPeerRemovedIkeSa,
		protocol.ERR_UNSUPPORTED_CRITICAL_PAYLOAD,
		protocol.ERR_INVALID_SYNTAX,
		protocol.ERR_AUTHENTICATION_FAILED:
		break
	default:
		sess.sendIkeSaDelete()
	}
	sess.RemoveSa()
	sess.removePolicy()
	// NOTE : it is possible that RunSession has exited already
	close(sess.incoming) // closing channel will cause RunSession to continue
	<-sess.cxt.Done()    // wait till it returns
}

// Housekeeping

func (sess *Session) IsInitiator() bool {
	return sess.isInitiator
}

type OutgoingMessage struct {
	Data []byte
}

func (sess *Session) tag() string {
	ini := "[I]"
	if !sess.isInitiator {
		ini = "[R]"
	}
	return ini + sess.IkeSpiI.String()
}

func (sess *Session) String() string {
	return fmt.Sprintf("%s<=>%s %s", sess.IkeSpiI, sess.IkeSpiR, sess.tkm)
}

func (sess *Session) CreateIkeSa(init *initParams) error {
	if sess.isInitiator {
		// peer responders nonce
		sess.tkm.Nr = init.nonce
		// peer responders spi
		sess.IkeSpiR = append([]byte{}, init.spiR...)
	} else {
		// peer initiators nonce
		sess.tkm.Ni = init.nonce
		// peer initiators spi
		sess.IkeSpiI = append([]byte{}, init.spiI...)
	}
	//
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// initialize dh shared with their public key
	err := sess.tkm.DhGenerateKey(init.dhPublic)
	if err != nil {
		return err
	}
	// peer will/not use secure signatures
	sess.rfc7427Signatures = init.rfc7427Signatures
	// create rest of ike sa
	sess.tkm.IkeSaKeys(sess.IkeSpiI, sess.IkeSpiR, nil)
	// create authenticators
	sess.authLocal = NewAuthenticator(sess.cfg.LocalID, sess.tkm, sess.isInitiator, sess.rfc7427Signatures)
	sess.authPeer = NewAuthenticator(sess.cfg.PeerID, sess.tkm, sess.isInitiator, sess.rfc7427Signatures)
	sess.Logger.Log("IKE_SA", "initialised", "session", sess, "securesig", init.rfc7427Signatures)
	return nil
}

func (sess *Session) SetCookie(cn *protocol.NotifyPayload) {
	sess.responderCookie = cn.NotificationMessage.([]byte)
}

func (sess *Session) PostMessage(msg *Message) {
	check := func() (err error) {
		if err = sess.isMessageValid(msg); err != nil {
			return
		}
		if err = DecryptMessage(msg, sess.tkm, sess.isInitiator, sess.Logger); err != nil {
			return
		}
		if sess.isClosing {
			err = errors.New("closing")
		}
		return
	}
	if err := check(); err != nil {
		level.Warn(sess.Logger).Log("DROP", err)
		return
	}
	sess.incoming <- msg
}

func (sess *Session) encode(msg *Message) (*OutgoingMessage, error) {
	buf, err := msg.Encode(sess.tkm, sess.isInitiator, sess.Logger)
	return &OutgoingMessage{buf}, err
}

func (sess *Session) sendMsg(msg *OutgoingMessage, err error) error {
	if err != nil {
		return err
	}
	return WriteData(sess.Conn, msg.Data, sess.Remote, sess.Logger)
}

// this can be used in genreal case, but not for INFO requests from responders -- TODO
func (sess *Session) nextID() (id uint32) {
	if sess.isInitiator {
		id = sess.msgIDReq.next()
	} else {
		id = sess.msgIDResp.next()
	}
	return
}

// InitMsg generates IKE_INIT
func (sess *Session) InitMsg() (*OutgoingMessage, error) {
	init := InitFromSession(sess)
	init.IkeHeader.MsgID = sess.nextID()
	// encode
	initB, err := sess.encode(init)
	if err != nil {
		return nil, err
	}
	if sess.isInitiator {
		sess.initIb = initB.Data
	} else {
		sess.initRb = initB.Data
	}
	return initB, nil
}

// AuthMsg generates IKE_AUTH
func (sess *Session) AuthMsg() (*OutgoingMessage, error) {
	sess.Logger.Log("TX_SELECTORS", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR))
	// make sure selectors are present
	if sess.cfg.TsI == nil || sess.cfg.TsR == nil {
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth, err := authFromSession(sess)
	if err != nil {
		sess.Logger.Log("ERROR", err)
		return nil, err
	}
	auth.IkeHeader.MsgID = sess.nextID()
	return sess.encode(auth)
}

func (sess *Session) RekeyMsg(child *Message) (*OutgoingMessage, error) {
	child.IkeHeader.MsgID = sess.nextID()
	// encode & send
	return sess.encode(child)
}

// SendMsgGetReply sends a request and waits for valid reply
func (sess *Session) SendMsgGetReply(genMsg func() (*OutgoingMessage, error)) (*Message, error) {
	for {
		// send initiator INIT after jittered wait
		if err := sess.sendMsg(genMsg()); err != nil {
			return nil, err
		}
		// wait for reply, or timeout
		msg, err := packetOrTimeOut(sess.incoming)
		if err != nil {
			// on timeout, send INIT again, and loop
			if err == errorReplyTimedout {
				continue
			}
			return nil, err
		}
		return msg, err
	}
}

// utilities

// CheckError checks error for error & sends notification within INFORMATIONAL
func (sess *Session) CheckError(err error, isResponse bool) error {
	if iErr, ok := errors.Cause(err).(protocol.IkeErrorCode); ok {
		sess.Notify(iErr, isResponse)
	}
	return err
}

func (sess *Session) AuthReply(ie error) {
	// send AUTH reply to peer & end IKE SA
	if iErr, ok := errors.Cause(ie).(protocol.IkeErrorCode); ok {
		reply := NotifyFromSession(sess, iErr, true)
		reply.IkeHeader.ExchangeType = protocol.IKE_AUTH
		reply.IkeHeader.MsgID = sess.nextID()
		// encode & send
		sess.sendMsg(sess.encode(reply))
	}
}

func (sess *Session) Notify(ie protocol.IkeErrorCode, isResponse bool) {
	info := NotifyFromSession(sess, ie, isResponse)
	info.IkeHeader.MsgID = sess.nextID()
	// encode & send
	sess.sendMsg(sess.encode(info))
}

func (sess *Session) sendIkeSaDelete() {
	info := DeleteFromSession(sess)
	info.IkeHeader.MsgID = sess.msgIDReq.next()
	// encode & send
	sess.sendMsg(sess.encode(info))
}

// SendEmptyInformational can be used for periodic keepalive
func (sess *Session) SendEmptyInformational(isResponse bool) error {
	info := EmptyFromSession(sess, isResponse)
	if isResponse {
		info.IkeHeader.MsgID = sess.msgIDResp.next()
	} else {
		info.IkeHeader.MsgID = sess.msgIDReq.next()
	}
	// encode & send
	return sess.sendMsg(sess.encode(info))
}

func (sess *Session) isMessageValid(msg *Message) error {
	if spi := msg.IkeHeader.SpiI; !bytes.Equal(spi, sess.IkeSpiI) {
		return errors.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	// for un-encrypted payloads, make sure that the state is correct
	if msg.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		// TODO -
	}
	// check sequence numbers
	seq := msg.IkeHeader.MsgID
	if msg.IkeHeader.Flags.IsResponse() {
		// response id ought to be same as our request id
		if seq != uint32(sess.msgIDReq.get()) {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected response id %d, expected %+v", seq, sess.msgIDReq))
		}
		sess.msgIDReq.confirm()
	} else {
		// request id ought to be one larger than the prev response
		if seq != uint32(sess.msgIDResp.get()+1) {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected request id %d, expected %+v", seq, sess.msgIDResp))
		}
		sess.msgIDResp.confirm()
	}
	return nil
}

// SetAddresses sets tunnel endpoint addresses
func (sess *Session) SetAddresses(local, remote net.Addr) error {
	sess.Local = local
	sess.Remote = remote
	if sess.cfg.TsI != nil && sess.cfg.TsR != nil {
		// selectors already configured
		return nil
	}
	return sess.cfg.AddHostSelectors(AddrToIp(local), AddrToIp(remote), sess.isInitiator)
}

func (sess *Session) saAddr() (net.IP, net.IP) {
	remoteIP := AddrToIp(sess.Remote)
	localIP := AddrToIp(sess.Local)
	if sess.isInitiator {
		return localIP, remoteIP
	}
	return remoteIP, localIP
}

// AddSa adds Child SA
func (sess *Session) AddSa(sa *platform.SaParams) (err error) {
	sa.Ini, sa.Res = sess.saAddr()
	sess.Logger.Log("INSTALL_SA",
		fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res))
	if sess.Cb.InstallChildSa != nil {
		err = sess.Cb.InstallChildSa(sess, sa)
	}
	return
}

// RemoveSa removes Child SA
func (sess *Session) RemoveSa() (err error) {
	if sess.EspSpiI == nil || sess.EspSpiR == nil {
		sess.Logger.Log("REMOVE_SA", "sa was not started")
		return
	}
	sa := removeSaParams(sess.EspSpiI, sess.EspSpiR, &sess.cfg)
	sa.Ini, sa.Res = sess.saAddr()
	sess.Logger.Log("REMOVE_SA",
		fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res))
	if sess.Cb.RemoveChildSa != nil {
		err = sess.Cb.RemoveChildSa(sess, sa)
	}
	return
}

func (sess *Session) installPolicy() (err error) {
	pol := sess.cfg.Policy()
	pol.Ini, pol.Res = sess.saAddr()
	sess.Logger.Log("INSTALL_POLICY",
		fmt.Sprintf("[%s]%s<=>%s[%s]", pol.Ini, pol.IniNet, pol.ResNet, pol.Res))
	if sess.Cb.InstallPolicy != nil {
		err = sess.Cb.InstallPolicy(sess, pol)
	}
	return
}

func (sess *Session) removePolicy() (err error) {
	if sess.EspSpiI == nil || sess.EspSpiR == nil {
		sess.Logger.Log("REMOVE_POLICY", "sa was not started")
		return
	}
	pol := sess.cfg.Policy()
	pol.Ini, pol.Res = sess.saAddr()
	sess.Logger.Log("REMOVE_POLICY",
		fmt.Sprintf("[%s]%s<=>%s[%s]", pol.Ini, pol.IniNet, pol.ResNet, pol.Res))
	if sess.Cb.RemovePolicy != nil {
		err = sess.Cb.RemovePolicy(sess, pol)
	}
	return
}
