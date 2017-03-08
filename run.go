package ike

import (
	"time"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

const SaRekeyTimeout = 5 * time.Second

func runInitiator(o *Session) error {
	// send initiator INIT after jittered wait and wait for reply
	time.Sleep(Jitter(4*time.Second, 1))
	msg, err := o.SendMsgGetReply(o.InitMsg)
	if err != nil {
		return err
	}
	// TODO - check if we already have a connection to this host
	// check if incoming message is an acceptable Init Response
	for {
		if err = CheckInitResponseForSession(o, msg); err != nil {
			if ce, ok := err.(CookieError); ok {
				// session is always returned for CookieError
				o.SetCookie(ce.Cookie)
				// send packet with Cookie
				if msg, err = o.SendMsgGetReply(o.InitMsg); err != nil {
					return err
				}
				// This will keep going if peer keeps sendign COOKIE
				// TODO -fix
				continue
			}
			// return error
			return err
		}
		break
	}
	// rewrite LocalAddr
	o.SetAddresses(msg.LocalAddr, msg.RemoteAddr)
	// COOKIE is handled within cmd.newSession
	if err = HandleInitForSession(o, msg); err != nil {
		o.Logger.Errorf("Error Initializing: %+v", err)
		return err
	}
	if err = o.AddHostBasedSelectors(AddrToIp(msg.LocalAddr), AddrToIp(msg.RemoteAddr)); err != nil {
		return err
	}
	// on send AUTH and wait for reply
	if msg, err = o.SendMsgGetReply(o.AuthMsg); err != nil {
		return err
	}
	if err = HandleAuthForSession(o, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	err = HandleSaForSession(o, msg)
	if err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	return nil
}

// got new INIT
func runResponder(o *Session) (err error) {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg := <-o.incoming
	if err = HandleInitForSession(o, msg); err != nil {
		return err
	}
	if err = o.AddHostBasedSelectors(AddrToIp(msg.LocalAddr), AddrToIp(msg.RemoteAddr)); err != nil {
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
	newTkm, err := NewTkm(&o.cfg, o.Logger, nil)
	if err != nil {
		return
	}
	espSpiI := MakeSpi()[:4]
	// closure with parameters for new SA
	rekeyFn := func() (*OutgoingMessge, error) {
		return o.RekeyMsg(o.SaRekey(newTkm, true, espSpiI))
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
	espSpiR, err := HandleSaRekey(o, newTkm, true, params)
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
	params, err := parseChildSa(msg)
	if err != nil {
		return
	}
	newTkm, err := NewTkm(&o.cfg, o.Logger, params.nonce)
	if err != nil {
		return
	}
	//  use new tkm to verify REKEY_reply and configure new SA
	espSpiI, err := HandleSaRekey(o, newTkm, false, params)
	if err != nil {
		return
	}
	espSpiR := MakeSpi()[:4]
	// closure with parameters for new SA
	err = o.sendMsg(o.RekeyMsg(o.SaRekey(newTkm, false, espSpiR)))
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

func monitorSa(o *Session) error {
	// inform user
	if err := o.InstallSa(); err != nil {
		return err
	}
	if o.isInitiator {
		// send INFORMATIONAL, wait for INFORMATIONAL_reply
		// if timeout, send AUTH_reply again
		// monitor SA
		if err := o.SendEmptyInformational(false); err != nil {
			return err
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
				if evt.NotificationType == MSG_EMPTY_REQUEST {
					if err := o.SendEmptyInformational(true); err != nil {
						return err
					}
				}
			case protocol.CREATE_CHILD_SA:
				// ONLY :
				// Accept SA rekey if responder
				if o.isInitiator {
					o.Logger.Info("Rekey Request: Currently only supported for responder")
					// send notification
					o.Notify(protocol.ERR_NO_ADDITIONAL_SAS)
					continue
				}
				if err := onIpsecRekey(o, msg); err != nil {
					return err
				}
				// if REKEY rx :
				//  send REKEY_reply
				//  install SA
				//  send INFORMATIONAL, wait for INFORMATIONAL_reply
				//  if timeout, send REKEY_reply again
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
				o.Logger.Info("Rekey Timeout: Currently only supported for initiator")
				continue
			}
			o.Logger.Info("Rekey Timeout")
			if err := runIpsecRekey(o); err != nil {
				o.Logger.Info("Rekey Error: %+v", err)
				continue
			}
			// reset timers
			saRekeyTimer.Reset(Jitter(SaRekeyTimeout, -0.2))
			saRekeyDeadline.Reset(SaRekeyTimeout)
		}
	}
}

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
