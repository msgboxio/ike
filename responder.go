package ike

import (
	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
)

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(parent context.Context, cfg *Config, initI *Message, log *logrus.Logger) (*Session, error) {
	cs, err := crypto.NewCipherSuite(cfg.ProposalIke, log)
	if err != nil {
		return nil, err
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp, log)
	if err != nil {
		return nil, err
	}
	// cast is safe since we already checked for presence of payloads
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}
	// creating tkm is expensive, should come after checks are positive
	tkm, err := NewTkmResponder(cs, espSuite, noI.Nonce)
	if err != nil {
		return nil, err
	}

	cxt, cancel := context.WithCancel(parent)

	o := &Session{
		Context:  cxt,
		cancel:   cancel,
		tkm:      tkm,
		cfg:      *cfg,
		IkeSpiI:  ikeSpiI,
		IkeSpiR:  MakeSpi(),
		EspSpiR:  MakeSpi()[:4],
		incoming: make(chan *Message, 10),
	}
	o.Logger = &logrus.Logger{
		Out:       log.Out,
		Formatter: &PrefixFormatter{Prefix: o.Tag()},
		Hooks:     log.Hooks,
		Level:     log.Level,
	}

	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator, o.Logger)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator, o.Logger)
	o.Fsm = state.NewFsm(o.Logger, state.ResponderTransitions(o), state.CommonTransitions(o))
	o.PostEvent(&state.StateEvent{Event: state.SMI_START})
	return o, nil
}
