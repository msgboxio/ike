package ike

import "github.com/Sirupsen/logrus"

// NewInitiator creates an initiator session
func NewInitiator(cfg *Config, sd *SessionData, log *logrus.Logger) (*Session, error) {
	tkm, err := NewTkm(cfg, log, nil)
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
