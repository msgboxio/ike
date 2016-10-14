package ike

import (
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

// NewInitiator creates an initiator session
func NewInitiator(parent context.Context, localID, remoteID Identity, cfg *Config) *Session {
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
		Context:           cxt,
		cancel:            cancel,
		isInitiator:       true,
		tkm:               tkm,
		cfg:               CopyConfig(cfg),
		IkeSpiI:           MakeSpi(),
		EspSpiI:           MakeSpi()[:4],
		incoming:          make(chan *Message, 10),
		outgoing:          make(chan []byte, 10),
		rfc7427Signatures: true,
	}

	o.authLocal = NewAuthenticator(localID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.authRemote = NewAuthenticator(remoteID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.Fsm = state.NewFsm(state.InitiatorTransitions(o), state.CommonTransitions(o))
	o.PostEvent(&state.StateEvent{Event: state.SMI_START})
	return o
}
