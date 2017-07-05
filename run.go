package ike

import (
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var (
	initJitter   = 2 * time.Second
	jitterFactor = -0.5
)

func runInitiator(sess *Session) (err error) {
	// send initiator INIT after jittered wait and wait for reply
	time.Sleep(Jitter(initJitter, jitterFactor))
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
		if err = checkInitResponseForSession(sess, init); err != nil {
			if ce, ok := err.(peerRequestsCookieError); ok {
				sess.SetCookie(ce.Cookie)
				sess.msgIDReq.reset(0)
				// This will keep going if peer keeps sending COOKIE
				// TODO -fix
				continue
			}
			// return error
			return
		}
		break
	}
	if err := sess.CreateIkeSa(init); err != nil {
		return err
	}
	// TODO
	// If there is NAT , then all the further communication is performed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// save message
	sess.initRb = msg.Data
	// start auth
	sess.EspSpiI = MakeSpi()[:4]
	// send AUTH and wait for reply
	if msg, err = sess.SendMsgGetReply(sess.AuthMsg); err != nil {
		return
	}
	// is it an AUTH response, and can we proceed
	if err = checkAuthResponseForSession(sess, msg); err != nil {
		return
	}
	// can we authenticate ?
	espSpiR, lifetime, err := handleAuthForSession(sess, msg)
	if err != nil {
		// send notification in INFORMATIONAL request to peer & end IKE SA
		sess.CheckError(err, false)
		return
	}
	// replace espSpiI & lifetime : MUTATION
	sess.EspSpiR = espSpiR
	if lifetime != 0 {
		sess.cfg.Lifetime = lifetime
	}
	return
}

// got new INIT
func runResponder(sess *Session) (err error) {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg, ok := <-sess.incoming
	if !ok {
		return errorSessionClosed
	}
	// fetch params already attached from prior parsing
	init, ok := msg.Params.(*initParams)
	if !ok {
		return errors.New("missing init parameters")
	}
	if err = sess.CreateIkeSa(init); err != nil {
		return
	}
	// TODO - NAT
	// save message
	sess.initIb = msg.Data
	// send INIT_reply & wait for AUTH
	msg, err = sess.SendMsgGetReply(sess.InitMsg)
	if err != nil {
		return
	}
	// is it an AUTH request
	if err = checkAuthRequestForSession(sess, msg); err != nil {
		return
	}
	// can we authenticate ?
	espSpiI, lifetime, err := handleAuthForSession(sess, msg)
	if err != nil {
		sess.AuthReply(err)
		return
	}
	// replace espSpiI & espSpiR : MUTATION
	sess.EspSpiI = espSpiI
	sess.EspSpiR = MakeSpi()[:4]
	if lifetime != 0 {
		sess.cfg.Lifetime = lifetime
	}
	// send AUTH_reply
	if err = sess.sendMsg(sess.AuthMsg()); err != nil {
		return
	}
	return
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
	rekeyFn := func() (*OutgoingMessage, error) {
		return sess.RekeyMsg(ChildSaFromSession(sess, newTkm, true, espSpiI))
	}
	msg, err := sess.SendMsgGetReply(rekeyFn)
	if err != nil {
		return
	}
	params, err := parseChildSa(msg, true)
	if err != nil {
		return
	}
	for _, n := range msg.Payloads.GetNotifications() {
		if nErr, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
			// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE etc
			// TODO - for now, we should simply end the IKE_SA
			err = errors.Wrap(nErr, "peer notified")
			return
		}
	}
	espSpiR, err := checkIpsecRekeyResponse(sess, params)
	if err != nil {
		// send notification in INFORMATIONAL request to peer & end IKE SA
		sess.CheckError(err, false)
		return
	}
	if params.dhPublic != nil {
		if err = newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return
		}
	}
	newTkm.Nr = params.nonce
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = sess.AddSa(addSaParams(sess.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&sess.cfg))
	if err != nil {
		return
	}
	// remove old sa
	sess.RemoveSa()
	// replace espSpiI & espSpiR : MUTATION
	sess.EspSpiI = espSpiI
	sess.EspSpiR = espSpiR
	if params.lifetime != 0 {
		sess.cfg.Lifetime = params.lifetime
	}
	return
}

func onRekeyRequest(sess *Session, msg *Message) (err error) {
	// if REKEY rx :
	params, err := parseChildSa(msg, false)
	if err != nil {
		return
	}
	espSpiI, err := checkIpsecRekeyRequest(sess, params)
	if err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err, true)
		return
	}
	// create tkm with new Nonce
	newTkm, err := NewTkm(&sess.cfg, params.nonce)
	if err != nil {
		return
	}
	if params.dhPublic != nil {
		if err = newTkm.DhGenerateKey(params.dhPublic); err != nil {
			return
		}
	}
	espSpiR := MakeSpi()[:4]
	//  send REKEY_reply
	// closure with parameters for new SA
	err = sess.sendMsg(sess.RekeyMsg(ChildSaFromSession(sess, newTkm, false, espSpiR)))
	if err != nil {
		return
	}
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = sess.AddSa(addSaParams(sess.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&sess.cfg))
	if err != nil {
		return
	}
	// remove old sa
	sess.RemoveSa()
	// replace espSpiI & espSpiR : MUTATION
	sess.EspSpiI = espSpiI
	sess.EspSpiR = espSpiR
	if params.lifetime != 0 {
		sess.cfg.Lifetime = params.lifetime
	}
	//  send INFORMATIONAL, wait for INFORMATIONAL_reply
	//  if timeout, send REKEY_reply again
	return
}

func monitorSa(sess *Session) (err error) {
	// install policy
	err = sess.installPolicy()
	if err != nil {
		return
	}
	// add INITIAL sa
	err = sess.AddSa(addSaParams(sess.tkm,
		sess.tkm.Ni, sess.tkm.Nr, nil, // NOTE : use the original SA
		sess.EspSpiI, sess.EspSpiR,
		&sess.cfg))
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
	rekeyTimeout := Jitter(rekeyDelay, jitterFactor)
	saRekeyTimer := time.NewTimer(rekeyTimeout)
	sess.Logger.Log("RekeyDeadline", rekeyDelay, "RekeyTimeout", rekeyTimeout)
	for {
		select {
		// TODO - use a timeout here
		case msg, ok := <-sess.incoming:
			if !ok {
				return errorSessionClosed
			}
			switch msg.IkeHeader.ExchangeType {
			// if INFORMATIONAL, send INFORMATIONAL_reply
			case protocol.INFORMATIONAL:
				evt := HandleInformationalForSession(sess, msg)
				if evt == nil {
					continue
				}
				switch evt.SessionNotificationType {
				case MSG_EMPTY_RESPONSE:
					break
				case MSG_EMPTY_REQUEST:
					if iErr := sess.SendEmptyInformational(true); iErr != nil {
						return iErr
					}
				case MSG_ERROR:
					iErr := evt.Message.(error)
					sess.Logger.Log("INFORMATIONAL", iErr)
					return iErr
				default:
					level.Warn(sess.Logger).Log("INFORMATIONAL", "unhandled", "NOTIFICATION", evt.Message)
				}
			case protocol.CREATE_CHILD_SA:
				// ONLY :
				// Accept SA rekey if responder
				if sess.isInitiator {
					level.Warn(sess.Logger).Log("CREATE_CHILD_SA", "Currently only supported for responder")
					// send notification
					sess.Notify(protocol.ERR_NO_ADDITIONAL_SAS, true)
					continue
				}
				if err = onRekeyRequest(sess, msg); err != nil {
					return err
				}
				// reset timers
				saRekeyTimer.Reset(rekeyTimeout)
				saRekeyDeadline.Reset(rekeyDelay)
			}
		case <-saRekeyDeadline.C:
			return errorRekeyDeadlineExceeded
		case <-saRekeyTimer.C:
			// ONLY :
			// Initiate SA rekey if initiator
			if !sess.isInitiator {
				level.Warn(sess.Logger).Log("RekeyTimeout", "Currently only supported for initiator")
				continue
			}
			sess.Logger.Log("Rekey", "Timeout")
			if err = runIpsecRekey(sess); err != nil {
				sess.Logger.Log("RekeyError", err)
				return
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
	sess.cancel()
	// err must not be nil
	return err
}
