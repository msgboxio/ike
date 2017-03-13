package ike

import (
	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/protocol"
)

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(cfg *Config, sd *SessionData, initI *Message, log *logrus.Logger) (*Session, error) {
	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}
	// cast is safe since we already checked for presence of payloads
	// assert ?
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	// creating tkm is expensive, should come after checks are positive
	tkm, err := NewTkm(cfg, log, noI.Nonce)
	if err != nil {
		return nil, err
	}

	o := &Session{
		tkm:         tkm,
		cfg:         *cfg,
		IkeSpiI:     ikeSpiI,
		IkeSpiR:     MakeSpi(),
		EspSpiR:     MakeSpi()[:4],
		incoming:    make(chan *Message, 10),
		SessionData: sd,
	}
	o.Logger = &logrus.Logger{
		Out:       log.Out,
		Formatter: &PrefixFormatter{Prefix: o.Tag()},
		Hooks:     log.Hooks,
		Level:     log.Level,
	}

	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator)
	return o, nil
}
