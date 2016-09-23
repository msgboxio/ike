package ike

import (
	"crypto/x509"

	"github.com/msgboxio/ike/protocol"
)

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, Identity) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) error
}

func authenticator(id Identity, tkm *Tkm, rfc7427Signatures bool) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{tkm: tkm}
	case *CertIdentity:
		cid := &CertAuthenticator{
			tkm:                tkm,
			authMethod:         protocol.AUTH_RSA_DIGITAL_SIGNATURE,
			signatureAlgorithm: x509.SHA1WithRSA, // cant be changed
		}
		if rfc7427Signatures {
			cid.authMethod = protocol.AUTH_DIGITAL_SIGNATURE
			cid.signatureAlgorithm = x509.SHA256WithRSA // by default
		}
		return cid
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
