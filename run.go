package ike

import (
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var ErrorRekeyDeadlineExceeded = errors.New("Rekey Deadline Exceeded")

const SaRekeyTimeout = 5 * time.Second

func runInitiator(sess *Session) (err error) {
	// send initiator INIT after jittered wait and wait for reply
	time.Sleep(Jitter(2*time.Second, -0.5))
	var msg *Message
	var init *initParams
	for {
		msg, err = sess.SendMsgGetReply(sess.InitMsg)
		if err != nil {
			return
		}
		// TODO - check if we already have a connection to this host
		// check if incoming message is an acceptable Init Response
		init, err = parseInit(msg)
		if err != nil {
			if init == nil {
				return
			}
		}
		if err = CheckInitResponseForSession(sess, init); err != nil {
			if ce, ok := err.(PeerRequestsCookieError); ok {
				// session is always returned for CookieError
				sess.SetCookie(ce.Cookie)
				// This will keep going if peer keeps sending COOKIE
				// TODO -fix
				continue
			}
			// return error
			return
		}
		break
	}
	// rewrite LocalAddr
	if err = sess.SetAddresses(msg.LocalAddr, msg.RemoteAddr); err != nil {
		return
	}
	// COOKIE is handled within cmd.newSession
	if err = HandleInitForSession(sess, init, msg); err != nil {
		level.Error(sess.Logger).Log("init", err)
		return
	}
	// on send AUTH and wait for reply
	if msg, err = sess.SendMsgGetReply(sess.AuthMsg); err != nil {
		return
	}
	if err = HandleAuthForSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		err = errors.Wrap(protocol.ERR_AUTHENTICATION_FAILED, err.Error())
		sess.CheckError(err)
		return
	}
	if err = HandleSaForSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
	}
	return
}

// got new INIT
func runResponder(sess *Session) (err error) {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg := <-sess.incoming
	init, err := parseInit(msg)
	if err != nil {
		return
	}
	if err = HandleInitForSession(sess, init, msg); err != nil {
		return
	}
	// not really necessary
	if err = sess.SetAddresses(msg.LocalAddr, msg.RemoteAddr); err != nil {
		return
	}
	// send INIT_reply & wait for AUTH
	msg, err = sess.SendMsgGetReply(sess.InitMsg)
	if err != nil {
		return
	}
	if err = HandleAuthForSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		err = errors.Wrap(protocol.ERR_AUTHENTICATION_FAILED, err.Error())
		sess.CheckError(err)
		return
	}
	if err = HandleSaForSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
		return
	}
	// send AUTH_reply
	if err := sess.SendAuth(); err != nil {
		return err
	}
	return nil
}

func runIpsecRekey(sess *Session) (err error) {
	// if REKEY timeout
	//  create new tkm, send REKEY, wait for REKEY_reply,
	//  retry on timeout
	newTkm, err := NewTkm(&sess.cfg, nil)
	if err != nil {
		return
	}
	espSpiI := MakeSpi()[:4]
	// closure with parameters for new SA
	rekeyFn := func() (*OutgoingMessge, error) {
		return sess.RekeyMsg(ChildSaFromSession(sess, newTkm, true, espSpiI))
	}
	msg, err := sess.SendMsgGetReply(rekeyFn)
	if err != nil {
		return
	}
	params, err := parseChildSa(msg)
	if err != nil {
		return
	}
	//  use new tkm to verify REKEY_reply and configure new SA
	espSpiR, err := HandleChildSaForSession(sess, newTkm, true, params)
	if err != nil {
		return
	}
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = sess.AddSa(addSaParams(sess.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&sess.cfg, true))
	if err != nil {
		return
	}
	// remove old sa
	sess.RemoveSa()
	// replace espSpiI & espSpiR
	sess.EspSpiI = espSpiI
	sess.EspSpiR = espSpiR
	return
}

func onIpsecRekey(sess *Session, msg *Message) (err error) {
	// if REKEY rx :
	params, err := parseChildSa(msg)
	if err != nil {
		return
	}
	newTkm, err := NewTkm(&sess.cfg, params.nonce)
	if err != nil {
		return
	}
	//  send REKEY_reply
	//  use new tkm to verify REKEY_reply and configure new SA
	espSpiI, err := HandleChildSaForSession(sess, newTkm, false, params)
	if err != nil {
		return
	}
	espSpiR := MakeSpi()[:4]
	// closure with parameters for new SA
	err = sess.sendMsg(sess.RekeyMsg(ChildSaFromSession(sess, newTkm, false, espSpiR)))
	if err != nil {
		return
	}
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = sess.AddSa(addSaParams(sess.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&sess.cfg, true))
	if err != nil {
		return
	}
	// remove old sa
	sess.RemoveSa()
	// replace espSpiI & espSpiR
	sess.EspSpiI = espSpiI
	sess.EspSpiR = espSpiR
	//  send INFORMATIONAL, wait for INFORMATIONAL_reply
	//  if timeout, send REKEY_reply again
	return
}

func monitorSa(sess *Session) (err error) {
	sa := addSaParams(sess.tkm,
		sess.tkm.Ni, sess.tkm.Nr, nil, // NOTE : use the original SA
		sess.EspSpiI, sess.EspSpiR,
		&sess.cfg,
		sess.isInitiator)
	// add INITIAL sa
	err = sess.AddSa(sa)
	if err != nil {
		return
	}
	if sess.isInitiator {
		// send INFORMATIONAL, wait for INFORMATIONAL_reply
		// if timeout, send AUTH_reply again
		// monitor SA
		if err = sess.SendEmptyInformational(false); err != nil {
			return
		}
	}
	// check for duplicate SA, if found remove one with smaller nonce
	// setup SA REKEY timeout (jittered) & monitoring
	rekeyDelay := sess.cfg.Lifetime
	saRekeyDeadline := time.NewTimer(rekeyDelay)
	sess.Logger.Log("RekeyDeadline", rekeyDelay)
	rekeyTimeout := Jitter(rekeyDelay, -0.2)
	saRekeyTimer := time.NewTimer(rekeyTimeout)
	sess.Logger.Log("RekeyTimeout", rekeyTimeout)
	for {
		select {
		case msg := <-sess.incoming:
			switch msg.IkeHeader.ExchangeType {
			// if INFORMATIONAL, send INFORMATIONAL_reply
			case protocol.INFORMATIONAL:
				evt := HandleInformationalForSession(sess, msg)
				switch evt.SessionNotificationType {
				case MSG_EMPTY_REQUEST:
					if err := sess.SendEmptyInformational(true); err != nil {
						return err
					}
				case MSG_DELETE_IKE_SA:
					return evt.Message.(error)
				}
			case protocol.CREATE_CHILD_SA:
				// ONLY :
				// Accept SA rekey if responder
				if sess.isInitiator {
					level.Warn(sess.Logger).Log("RekeyRequest", "Currently only supported for responder")
					// send notification
					sess.Notify(protocol.ERR_NO_ADDITIONAL_SAS)
					continue
				}
				if err := onIpsecRekey(sess, msg); err != nil {
					return err
				}
				// reset timers
				saRekeyTimer.Reset(rekeyTimeout)
				saRekeyDeadline.Reset(rekeyDelay)
			}
		case <-saRekeyDeadline.C:
			return ErrorRekeyDeadlineExceeded
		case <-saRekeyTimer.C:
			// ONLY :
			// Initiate SA rekey if initiator
			if !sess.isInitiator {
				level.Warn(sess.Logger).Log("RekeyTimeout", "Currently only supported for initiator")
				continue
			}
			sess.Logger.Log("Rekey", "Timeout")
			if err := runIpsecRekey(sess); err != nil {
				sess.Logger.Log("RekeyError", err)
				continue
			}
			// reset timers
			saRekeyTimer.Reset(rekeyTimeout)
			saRekeyDeadline.Reset(rekeyDelay)
		} // select
	} // for
}

// RunSession starts and monitors the session returning when the session ends
func RunSession(sess *Session) error {
	var err error
	if sess.isInitiator {
		err = runInitiator(sess)
	} else {
		err = runResponder(sess)
	}
	if err == nil {
		err = monitorSa(sess)
	}
	return err
}
