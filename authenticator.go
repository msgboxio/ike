package ike

import (
	"crypto/x509"

	"github.com/msgboxio/ike/protocol"
)

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, Identity) []byte
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) bool
	SetUserCertificate(*x509.Certificate)
}

func authenticator(id Identity, tkm *Tkm) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{tkm: tkm}
	case *RsaCertIdentity:
		return &RsaCert{tkm: tkm}
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
