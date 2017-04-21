package ike

import (
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var ErrorRekeyDeadlineExceeded = errors.New("Rekey Deadline Exceeded")

const SaRekeyTimeout = 5 * time.Second

func runInitiator(o *Session) (err error) {
	// send initiator INIT after jittered wait and wait for reply
	time.Sleep(Jitter(2*time.Second, -0.5))
	var msg *Message
	var init *initParams
	for {
		msg, err = o.SendMsgGetReply(o.InitMsg)
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
		if err = CheckInitResponseForSession(o, init); err != nil {
			if ce, ok := err.(PeerRequestsCookieError); ok {
				// session is always returned for CookieError
				o.SetCookie(ce.Cookie)
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
	if err = o.SetAddresses(msg.LocalAddr, msg.RemoteAddr); err != nil {
		return
	}
	// COOKIE is handled within cmd.newSession
	if err = HandleInitForSession(o, init, msg); err != nil {
		level.Error(o.Logger).Log("init", err)
		return
	}
	// on send AUTH and wait for reply
	if msg, err = o.SendMsgGetReply(o.AuthMsg); err != nil {
		return
	}
	if err = HandleAuthForSession(o, msg); err != nil {
		// send notification to peer & end IKE SA
		err = errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
		return
	}
	if err = HandleSaForSession(o, msg); err != nil {
		// send notification to peer & end IKE SA
		err = errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	return
}

// got new INIT
func runResponder(o *Session) error {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg := <-o.incoming
	init, err := parseInit(msg)
	if err != nil {
		return err
	}
	if err = HandleInitForSession(o, init, msg); err != nil {
		return err
	}
	// not really necessary
	if err = o.SetAddresses(msg.LocalAddr, msg.RemoteAddr); err != nil {
		return err
	}
	// send INIT_reply & wait for AUTH
	msg, err = o.SendMsgGetReply(o.InitMsg)
	if err != nil {
		return err
	}
	if err := HandleAuthForSession(o, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	// install SA;
	if err := HandleSaForSession(o, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	// send AUTH_reply
	if err := o.SendAuth(); err != nil {
		return err
	}
	return nil
}

func runIpsecRekey(o *Session) (err error) {
	// if REKEY timeout
	//  create new tkm, send REKEY, wait for REKEY_reply,
	//  retry on timeout
	newTkm, err := NewTkm(&o.cfg, nil)
	if err != nil {
		return
	}
	espSpiI := MakeSpi()[:4]
	// closure with parameters for new SA
	rekeyFn := func() (*outgoingMessge, error) {
		return o.RekeyMsg(ChildSaFromSession(o, newTkm, true, espSpiI))
	}
	msg, err := o.SendMsgGetReply(rekeyFn)
	if err != nil {
		return
	}
	params, err := parseChildSa(msg)
	if err != nil {
		return
	}
	//  use new tkm to verify REKEY_reply and configure new SA
	espSpiR, err := HandleChildSaForSession(o, newTkm, true, params)
	if err != nil {
		return
	}
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = o.AddSa(addSaParams(o.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&o.cfg, true))
	if err != nil {
		return
	}
	// remove old sa
	o.UnInstallSa()
	// replace espSpiI & espSpiR
	o.EspSpiI = espSpiI
	o.EspSpiR = espSpiR
	return
}

func onIpsecRekey(o *Session, msg *Message) (err error) {
	// if REKEY rx :
	params, err := parseChildSa(msg)
	if err != nil {
		return
	}
	newTkm, err := NewTkm(&o.cfg, params.nonce)
	if err != nil {
		return
	}
	//  send REKEY_reply
	//  use new tkm to verify REKEY_reply and configure new SA
	espSpiI, err := HandleChildSaForSession(o, newTkm, false, params)
	if err != nil {
		return
	}
	espSpiR := MakeSpi()[:4]
	// closure with parameters for new SA
	err = o.sendMsg(o.RekeyMsg(ChildSaFromSession(o, newTkm, false, espSpiR)))
	if err != nil {
		return
	}
	// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
	err = o.AddSa(addSaParams(o.tkm,
		newTkm.Ni, newTkm.Nr, newTkm.DhShared,
		espSpiI, espSpiR,
		&o.cfg, true))
	if err != nil {
		return
	}
	// remove old sa
	o.UnInstallSa()
	// replace espSpiI & espSpiR
	o.EspSpiI = espSpiI
	o.EspSpiR = espSpiR
	//  send INFORMATIONAL, wait for INFORMATIONAL_reply
	//  if timeout, send REKEY_reply again
	return
}

func monitorSa(o *Session) (err error) {
	// inform user
	err = o.AddSa(addSaParams(o.tkm,
		o.tkm.Ni, o.tkm.Nr, nil, // NOTE : use the original SA
		o.EspSpiI, o.EspSpiR,
		&o.cfg,
		o.isInitiator))
	if err != nil {
		return
	}
	if o.isInitiator {
		// send INFORMATIONAL, wait for INFORMATIONAL_reply
		// if timeout, send AUTH_reply again
		// monitor SA
		if err = o.SendEmptyInformational(false); err != nil {
			return
		}
	}
	// check for duplicate SA, if found remove one with smaller nonce
	// setup SA REKEY timeout (jittered) & monitoring
	saRekeyTimer := time.NewTimer(Jitter(SaRekeyTimeout, -0.2))
	saRekeyDeadline := time.NewTimer(SaRekeyTimeout)
	for {
		select {
		case msg := <-o.incoming:
			switch msg.IkeHeader.ExchangeType {
			// if INFORMATIONAL, send INFORMATIONAL_reply
			case protocol.INFORMATIONAL:
				evt := HandleInformationalForSession(o, msg)
				switch evt.NotificationType {
				case MSG_EMPTY_REQUEST:
					if err := o.SendEmptyInformational(true); err != nil {
						return err
					}
				case MSG_DELETE_IKE_SA:
					return evt.Message.(error)
				}
			case protocol.CREATE_CHILD_SA:
				// ONLY :
				// Accept SA rekey if responder
				if o.isInitiator {
					o.Logger.Log("warn", "Rekey Request: Currently only supported for responder")
					// send notification
					o.Notify(protocol.ERR_NO_ADDITIONAL_SAS)
					continue
				}
				if err := onIpsecRekey(o, msg); err != nil {
					return err
				}
				// reset timers
				saRekeyTimer.Reset(Jitter(SaRekeyTimeout, -0.2))
				saRekeyDeadline.Reset(SaRekeyTimeout)
			}
		case <-saRekeyDeadline.C:
			return ErrorRekeyDeadlineExceeded
		case <-saRekeyTimer.C:
			// ONLY :
			// Initiate SA rekey if initiator
			if !o.isInitiator {
				o.Logger.Log("warn", "Rekey Timeout: Currently only supported for initiator")
				continue
			}
			o.Logger.Log("note", "Rekey Timeout")
			if err := runIpsecRekey(o); err != nil {
				o.Logger.Log("error:", err)
				continue
			}
			// reset timers
			saRekeyTimer.Reset(Jitter(SaRekeyTimeout, -0.2))
			saRekeyDeadline.Reset(SaRekeyTimeout)
		}
	}
}

// RunSession starts and monitors the session returning when the session ends
func RunSession(s *Session) error {
	var err error
	if s.isInitiator {
		err = runInitiator(s)
	} else {
		err = runResponder(s)
	}
	if err == nil {
		err = monitorSa(s)
	}
	return err
}
