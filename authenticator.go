package ike

import "github.com/msgboxio/ike/protocol"

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, Identity) []byte
	Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) bool
}

func authenticator(id Identity, tkm *Tkm) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &PskAuthenticator{tkm}
	case *RsaCertIdentity:
		return &RsaCert{tkm}
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}
