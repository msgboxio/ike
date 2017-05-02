package ike

import (
	"bytes"
	"fmt"
	"math/big"
	"net"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// SessionCallback holds the callbacks used by the session to notify the user
type SessionCallback struct {
	AddSa    func(*Session, *platform.SaParams) error
	RemoveSa func(*Session, *platform.SaParams) error
}

type sessionClosed struct{}

func (s sessionClosed) Error() string {
	return "Session Closed"
}

var SessionClosedError error = sessionClosed{}

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
	o := &Session{
		isInitiator: true,
		tkm:         tkm,
		cfg:         *cfg,
		IkeSpiI:     MakeSpi(),
		EspSpiI:     MakeSpi()[:4],
		incoming:    make(chan *Message, 10),
		Conn:        conn,
		Remote:      remoteAddr,
		Cb:          *cb,
	}
	o.Logger = log.With(logger, "session", o.tag())
	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator)
	return o, nil
}

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(cfg *Config, conn Conn, cb *SessionCallback, initI *Message, logger log.Logger) (*Session, error) {
	// consider creating a new session
	if err := HandleInitRequest(initI, conn, cfg, logger); err != nil {
		// dont create a new session
		return nil, err
	}
	// get spi
	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}
	// cast is safe since we already checked for presence of payloads
	// assert ?
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	// creating tkm is expensive, should come after checks are positive
	tkm, err := NewTkm(cfg, noI.Nonce)
	if err != nil {
		return nil, err
	}
	// create and run session
	sess := &Session{
		tkm:      tkm,
		cfg:      *cfg,
		IkeSpiI:  ikeSpiI,
		IkeSpiR:  MakeSpi(),
		EspSpiR:  MakeSpi()[:4],
		incoming: make(chan *Message, 10),
		Conn:     conn,
		Local:    initI.LocalAddr,
		Remote:   initI.RemoteAddr,
		Cb:       *cb,
	}
	sess.Logger = log.With(logger, "session", sess.tag())
	sess.authLocal = NewAuthenticator(cfg.LocalID, sess.tkm, cfg.AuthMethod, sess.isInitiator)
	sess.authRemote = NewAuthenticator(cfg.RemoteID, sess.tkm, cfg.AuthMethod, sess.isInitiator)
	return sess, nil
}

// Destructors

// Close is called to initiate a session shutdown
func (sess *Session) Close(err error) {
	sess.Logger.Log("msg", "Close Session", "err", err)
	if sess.isClosing {
		return
	}
	sess.isClosing = true
	sess.sendIkeSaDelete()
	sess.RemoveSa()
}

// HandleClose will cleanly removes child SAs upon receiving a message from peer
func (sess *Session) HandleClose() {
	if sess.isClosing {
		return
	}
	sess.isClosing = true
	sess.SendEmptyInformational(true)
	sess.RemoveSa()
}

// Housekeeping

type OutgoingMessge struct {
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

func (sess *Session) CreateIkeSa(nonce, dhPublic *big.Int, spiI, spiR []byte) error {
	if sess.isInitiator {
		// peer responders nonce
		sess.tkm.Nr = nonce
		// peer responders spi
		sess.IkeSpiR = append([]byte{}, spiR...)
	} else {
		// peer initiators nonce
		sess.tkm.Ni = nonce
		// peer initiators spi
		sess.IkeSpiI = append([]byte{}, spiI...)
	}
	//
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// initialize dh shared with their public key
	err := sess.tkm.DhGenerateKey(dhPublic)
	if err != nil {
		return err
	}
	// create rest of ike sa
	sess.tkm.IkeSaKeys(sess.IkeSpiI, sess.IkeSpiR, nil)
	sess.Logger.Log("IKE_SA", "initialised", "session", sess)
	return nil
}

func (sess *Session) SetCookie(cn *protocol.NotifyPayload) {
	sess.responderCookie = cn.NotificationMessage.([]byte)
}

func (sess *Session) PostMessage(m *Message) {
	check := func() (err error) {
		if err = sess.isMessageValid(m); err != nil {
			return
		}
		if err = DecryptMessage(m, sess.tkm, sess.isInitiator, sess.Logger); err != nil {
			return
		}
		if sess.isClosing {
			err = errors.New("closing")
		}
		return
	}
	if err := check(); err != nil {
		level.Warn(sess.Logger).Log("DROP", fmt.Sprintf("%+v", err))
	}
	// requestId has been confirmed, increment it for next request
	sess.msgIDReq++
	sess.incoming <- m
}

func (sess *Session) encode(msg *Message) (*OutgoingMessge, error) {
	buf, err := msg.Encode(sess.tkm, sess.isInitiator, sess.Logger)
	return &OutgoingMessge{buf}, err
}

func (sess *Session) sendMsg(msg *OutgoingMessge, err error) error {
	if err != nil {
		return err
	}
	return WriteData(sess.Conn, msg.Data, sess.Remote, sess.Logger)
}

// nextMsgID increments and returns response ids for responses, returns request ids as is
func (sess *Session) nextMsgID(isResponse bool) (msgID uint32) {
	if isResponse {
		msgID = sess.msgIDResp
		sess.msgIDResp++
	} else {
		msgID = sess.msgIDReq
	}
	return
}

// InitMsg generates IKE_INIT
func (sess *Session) InitMsg() (*OutgoingMessge, error) {
	initMsg := func(msgId uint32) (*OutgoingMessge, error) {
		init := InitFromSession(sess)
		init.IkeHeader.MsgID = msgId
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
	// reset request ID to 0 - needed when resending with COOKIE
	sess.msgIDReq = 0
	return initMsg(sess.nextMsgID(!sess.isInitiator)) // is a response if not an initiator
}

// AuthMsg generates IKE_AUTH
func (sess *Session) AuthMsg() (*OutgoingMessge, error) {
	sess.Logger.Log("msg", "AUTH", "selectors", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR))
	// make sure selectors are present
	if sess.cfg.TsI == nil || sess.cfg.TsR == nil {
		return nil, errors.WithStack(protocol.ERR_NO_PROPOSAL_CHOSEN)
	}
	auth, err := AuthFromSession(sess)
	if err != nil {
		sess.Logger.Log("err", err)
		return nil, err
	}
	auth.IkeHeader.MsgID = sess.nextMsgID(!sess.isInitiator) // is a response if not an initiator
	return sess.encode(auth)
}

func (sess *Session) RekeyMsg(child *Message) (*OutgoingMessge, error) {
	child.IkeHeader.MsgID = sess.nextMsgID(!sess.isInitiator) // is a response if not an initiator
	// encode & send
	return sess.encode(child)
}

// SendMsgGetReply takes a message generator
func (sess *Session) SendMsgGetReply(genMsg func() (*OutgoingMessge, error)) (*Message, error) {
	for {
		// send initiator INIT after jittered wait
		if err := sess.sendMsg(genMsg()); err != nil {
			return nil, err
		}
		// wait for reply, or timeout
		msg, err := packetOrTimeOut(sess.incoming)
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
func (sess *Session) SendAuth() error {
	return sess.sendMsg(sess.AuthMsg())
}

// CheckError checks error, then send to peer
func (sess *Session) CheckError(err error) error {
	if iErr, ok := errors.Cause(err).(protocol.IkeErrorCode); ok {
		sess.Notify(iErr)
		return nil
	}
	return err
}

// utilities

func (sess *Session) Notify(ie protocol.IkeErrorCode) {
	info := NotifyFromSession(sess, ie)
	info.IkeHeader.MsgID = sess.nextMsgID(false) // never a response
	// encode & send
	sess.sendMsg(sess.encode(info))
}

func (sess *Session) sendIkeSaDelete() {
	info := DeleteFromSession(sess)
	info.IkeHeader.MsgID = sess.nextMsgID(false) // never a response
	// encode & send
	sess.sendMsg(sess.encode(info))
}

// SendEmptyInformational can be used for periodic keepalive
func (sess *Session) SendEmptyInformational(isResponse bool) error {
	info := EmptyFromSession(sess, isResponse)
	info.IkeHeader.MsgID = sess.nextMsgID(isResponse)
	// encode & send
	return sess.sendMsg(sess.encode(info))
}

func (sess *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, sess.IkeSpiI) {
		return errors.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_SA_INIT does not have it
	// for un-encrypted payloads, make sure that the state is correct
	if m.IkeHeader.NextPayload != protocol.PayloadTypeSK {
		// TODO -
	}
	// check sequence numbers
	seq := m.IkeHeader.MsgID
	if m.IkeHeader.Flags.IsResponse() {
		// response id ought to be the same as our request id
		if seq != sess.msgIDReq {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected response id %d, expected %d", seq, sess.msgIDReq))
		}
	} else { // request
		// TODO - does not handle our responses getting lost
		if seq != sess.msgIDResp {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID,
				fmt.Sprintf("unexpected request id %d, expected %d", seq, sess.msgIDResp))
		}
		// incremented by sender
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
	return sess.cfg.AddHostBasedSelectors(AddrToIp(local), AddrToIp(remote), sess.isInitiator)
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

// AddSa adds Child SA
func (sess *Session) AddSa(sa *platform.SaParams) (err error) {
	saAddr(sa, sess.Local, sess.Remote)
	sess.Logger.Log("CHILD_SA", "install",
		"sa", fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res))
	if sess.Cb.AddSa != nil {
		err = sess.Cb.AddSa(sess, sa)
	}
	return
}

// RemoveSa removes Child SA
func (sess *Session) RemoveSa() (err error) {
	if (sess.Local == nil) || sess.Remote == nil {
		// sa was not started
		return
	}
	sa := removeSaParams(
		sess.EspSpiI, sess.EspSpiR,
		&sess.cfg,
		sess.isInitiator)
	saAddr(sa, sess.Local, sess.Remote)
	sess.Logger.Log("CHILD_SA", "remove",
		"sa", fmt.Sprintf("%#x<=>%#x; [%s]%s<=>%s[%s]", sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res))
	if sess.Cb.RemoveSa != nil {
		err = sess.Cb.RemoveSa(sess, sa)
	}
	return
}
