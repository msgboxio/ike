package ike

import (
	"github.com/go-kit/kit/log"
)

// NewInitiator creates an initiator session
func NewInitiator(cfg *Config, sd *SessionData, logger log.Logger) (*Session, error) {
	tkm, err := NewTkm(cfg, nil)
	if err != nil {
		return nil, err
	}

	o := &Session{
		isInitiator: true,
		tkm:         tkm,
		cfg:         *cfg,
		IkeSpiI:     MakeSpi(),
		EspSpiI:     MakeSpi()[:4],
		incoming:    make(chan *Message, 10),
		SessionData: sd,
	}
	o.Logger = log.With(logger, "session", o.Tag())

	o.authLocal = NewAuthenticator(cfg.LocalID, o.tkm, cfg.AuthMethod, o.isInitiator)
	o.authRemote = NewAuthenticator(cfg.RemoteID, o.tkm, cfg.AuthMethod, o.isInitiator)
	return o, nil
}
