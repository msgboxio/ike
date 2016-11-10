package ike

import (
	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/state"
)

// NewInitiator creates an initiator session
func NewInitiator(parent context.Context, cfg *Config, log *logrus.Logger) (*Session, error) {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke, log)
	if err != nil {
		return nil, err
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp, log)
	if err != nil {
		return nil, err
	}

	tkm, err := NewTkmInitiator(suite, espSuite)
	if err != nil {
		return nil, err
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
	o.Logger = &logrus.Logger{
		Out:       log.Out,
		Formatter: &PrefixFormatter{Prefix: o.Tag()},
		Hooks:     log.Hooks,
		Level:     log.Level,
	}

	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator, o.Logger)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator, o.Logger)
	o.Fsm = state.NewFsm(o.Logger, state.InitiatorTransitions(o), state.CommonTransitions(o))
	o.PostEvent(&state.StateEvent{Event: state.SMI_START})

	return o, nil
}
