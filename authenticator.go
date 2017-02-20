package ike

import (
	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/protocol"
)

// Authenticator is used to authenticate & create AUTH payloads
type Authenticator interface {
	Identity() Identity
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte) error
}

func NewAuthenticator(id Identity, tkm *Tkm, authMethod protocol.AuthMethod, forInitiator bool, log *logrus.Logger) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
			log:          log,
		}
	case *CertIdentity:
		cid := &CertAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
			authMethod:   authMethod,
			log:          log,
		}
		return cid
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
