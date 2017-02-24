package ike

import (
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

func runInitiator(s *Session) error {
	// send initiator INIT after jittered wait
	if err := s.SendInit(); err != nil {
		return err
	}
	// wait for reply, or timeout
	msg := <-s.incoming
	// on timeout, send INIT again, and loop
	// COOKIE is handled within cmd.newSession
	if err := HandleInitForSession(s, msg); err != nil {
		s.Logger.Errorf("Error Initializing: %+v", err)
		return err
	}
	// on INIT reply send AUTH
	if err := s.SendAuth(); err != nil {
		return err
	}
	// wait for AUTH reply or timeout
	msg = <-s.incoming
	// on timeout, send again, and loop
	if err := HandleAuthForSession(s, msg); err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	err := HandleSaForSession(s, msg)
	if err != nil {
		// send notification to peer & end IKE SA
		return errors.Wrapf(protocol.ERR_AUTHENTICATION_FAILED, "%s", err)
	}
	// inform user
	s.InstallSa()
	// install SA
	// monitorSa
	return nil
}

// got new INIT
func runResponder(s *Session) error {
	// wait for INIT
	// send COOKIE, wait - handled by cmd:newSession
	// get INIT
	msg := <-s.incoming
	if err := HandleInitForSession(s, msg); err != nil {
		s.Logger.Errorf("Error Initializing: %+v", err)
		return err
	}
	// send INIT_reply & wait for AUTH
	if err := s.SendInit(); err != nil {
		return err
	}
	msg = <-s.incoming
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
	// on timeout, send again, and loop
	if err := s.SendAuth(); err != nil {
		return err
	}
	// send INFORMATIONAL, wait for INFORMATIONAL_reply
	// if timeout, send AUTH_reply again
	// monitor SA
	s.InstallSa()
	return nil
}

func monitorSa() {
	for {

	}
	// check for duplicate SA, if found remove one with smaller nonce
	// setup REKEY timeout (jittered) & monitoring
	// if INFORMATIONAL, send INFORMATIONAL_reply
	// if REKEY timeout
	//  create new tkm, send REKEY, wait for REKEY_reply,
	//  retry on timeout
	//  use new tkm to verify REKEY_reply and configure new SA
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
		monitorSa()
	}
	return err
}
