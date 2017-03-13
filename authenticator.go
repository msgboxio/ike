package ike

import (
	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
)

// Authenticator is used to authenticate & create AUTH payloads
type Authenticator interface {
	Identity() Identity
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, log.Logger) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte, logger log.Logger) error
}

func NewAuthenticator(id Identity, tkm *Tkm, authMethod protocol.AuthMethod, forInitiator bool) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
		}
	case *CertIdentity:
		cid := &CertAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
			authMethod:   authMethod,
		}
		return cid
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
