package ike

import (
	"time"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

const SaRekeyTimeout = 5 * time.Second

func runInitiator(s *Session) error {
	// send initiator INIT after jittered wait and wait for reply
	time.Sleep(Jitter(4*time.Second, 1))
	msg, err := s.SendMsgGetReply(s.InitMsg)
	if err != nil {
		return err
	}
	// TODO - check if we already have a connection to this host
	// check if incoming message is an acceptable Init Response
	for {
		if err = CheckInitResponseForSession(s, msg); err != nil {
			if ce, ok := err.(CookieError); ok {
				// session is always returned for CookieError
				s.SetCookie(ce.Cookie)
				// send packet with Cookie
				if msg, err = s.SendMsgGetReply(s.InitMsg); err != nil {
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
	s.SetAddresses(msg.LocalAddr, msg.RemoteAddr)
	// COOKIE is handled within cmd.newSession
	if err = HandleInitForSession(s, msg); err != nil {
		s.Logger.Errorf("Error Initializing: %+v", err)
		return err
	}
	if err = s.AddHostBasedSelectors(AddrToIp(msg.LocalAddr), AddrToIp(msg.RemoteAddr)); err != nil {
		return err
	}
	// on send AUTH and wait for reply
	if msg, err = s.SendMsgGetReply(s.AuthMsg); err != nil {
		return err
	}
	if err = HandleAuthForSession(s, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	err = HandleSaForSession(s, msg)
	if err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	return nil
}

// got new INIT
func runResponder(s *Session) (err error) {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg := <-s.incoming
	if err = HandleInitForSession(s, msg); err != nil {
		return err
	}
	if err = s.AddHostBasedSelectors(AddrToIp(msg.LocalAddr), AddrToIp(msg.RemoteAddr)); err != nil {
		return err
	}
	// send INIT_reply & wait for AUTH
	msg, err = s.SendMsgGetReply(s.InitMsg)
	if err != nil {
		return err
	}
	if err := HandleAuthForSession(s, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	// install SA;
	if err := HandleSaForSession(s, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	// send AUTH_reply
	if err := s.SendAuth(); err != nil {
		return err
	}
	return nil
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
			}
		case <-saRekeyDeadline.C:
			return ErrorRekeyDeadlineExceeded
		case <-saRekeyTimer.C:
			// ONLY :
			// SA rekey from original initiator
			if !o.isInitiator {
				o.Logger.Info("Rekey Timeout: Currently only supported for initiator")
				continue
			}
			o.Logger.Info("Rekey Timeout")
			// if REKEY timeout
			//  create new tkm, send REKEY, wait for REKEY_reply,
			//  retry on timeout
			newTkm, err := NewTkm(&o.cfg, o.Logger, nil)
			if err != nil {
				return err
			}
			espSpiI := MakeSpi()[:4]
			// closure with parameters for new SA
			rekeyFn := func() (*OutgoingMessge, error) {
				return o.SaRekey(newTkm, true, espSpiI)
			}
			msg, err := o.SendMsgGetReply(rekeyFn)
			if err != nil {
				return err
			}
			//  use new tkm to verify REKEY_reply and configure new SA
			espSpiR, err := HandleSaRekey(o, newTkm, true, msg)
			if err != nil {
				return err
			}
			// install new SA - [espSpiI, espSpiR, nI, nR & dhShared]
			err = o.AddSa(addSa(o.tkm,
				newTkm.Ni, newTkm.Nr, newTkm.DhShared,
				espSpiI, espSpiR,
				&o.cfg, true))
			if err != nil {
				return err
			}
			// remove old sa
			o.UnInstallSa()
			// replace espSpiI & espSpiR
			o.EspSpiI = espSpiI
			o.EspSpiR = espSpiR
			// reset timers
			saRekeyDeadline.Reset(SaRekeyTimeout)
			saRekeyTimer.Reset(Jitter(SaRekeyTimeout, -0.2))
		}
	}
	// if REKEY rx :
	//  send REKEY_reply
	//  install SA
	//  send INFORMATIONAL, wait for INFORMATIONAL_reply
	//  if timeout, send REKEY_reply again
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
