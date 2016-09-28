package ike

import (
	"crypto/x509"

	"github.com/msgboxio/ike/protocol"
)

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	Identity() Identity
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte) error
}

func NewAuthenticator(id Identity, tkm *Tkm, rfc7427Signatures bool, forInitiator bool) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{
			tkm:          tkm,
			forInitiator: forInitiator,
			identity:     id,
		}
	case *CertIdentity:
		cid := &CertAuthenticator{
			tkm:                tkm,
			forInitiator:       forInitiator,
			identity:           id,
			authMethod:         protocol.AUTH_RSA_DIGITAL_SIGNATURE,
			signatureAlgorithm: x509.SHA1WithRSA, // cant be changed
		}
		if rfc7427Signatures {
			cid.authMethod = protocol.AUTH_DIGITAL_SIGNATURE
			cid.signatureAlgorithm = x509.SHA256WithRSA // default, can change
		}
		return cid
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
