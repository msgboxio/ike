package ike

import "github.com/msgboxio/ike/protocol"

// Authenticator interface is used to authenticate / create AUTH payloads
type Authenticator interface {
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, Identities) []byte
}
