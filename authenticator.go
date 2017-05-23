package ike

import (
	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
)

// Authenticator is used to authenticate & create AUTH payloads
type Authenticator interface {
	Identity() Identity
	Sign([]byte, *protocol.IdPayload, log.Logger) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte, inbandData interface{}, logger log.Logger) error
}

func NewAuthenticator(id Identity, tkm *Tkm, forInitiator, rfc7427Signatures bool) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
		}
	case *CertIdentity:
		return &CertAuthenticator{
			tkm:               tkm,
			forInitiator:      forInitiator,
			identity:          id,
			rfc7427Signatures: rfc7427Signatures,
		}
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
