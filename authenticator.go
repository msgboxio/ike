package ike

import "github.com/msgboxio/ike/protocol"

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	Identity() Identity
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte) error
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
