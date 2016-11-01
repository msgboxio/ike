package ike

import (
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

// NewInitiator creates an initiator session
func NewInitiator(parent context.Context, cfg *Config) *Session {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		log.Error(err)
		return nil
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp)
	if err != nil {
		log.Error(err)
		return nil
	}

	tkm, err := NewTkmInitiator(suite, espSuite)
	if err != nil {
		log.Error(err)
		return nil
	}

	cxt, cancel := context.WithCancel(parent)
	o := &Session{
		Context:     cxt,
		cancel:      cancel,
		isInitiator: true,
		tkm:         tkm,
		cfg:         *cfg,
		IkeSpiI:     MakeSpi(),
		EspSpiI:     MakeSpi()[:4],
		incoming:    make(chan *Message, 10),
	}

	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator)
	o.Fsm = state.NewFsm(state.InitiatorTransitions(o), state.CommonTransitions(o))
	o.PostEvent(&state.StateEvent{Event: state.SMI_START})
	return o
}
