package ike

import (
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

// TODO:
// currently support for signature authenticaiton is limited to
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// &
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
// AUTH_ECDSA_256                         AuthMethod = 9  // RFC4754
// AUTH_ECDSA_384                         AuthMethod = 10 // RFC4754
// AUTH_ECDSA_521                         AuthMethod = 11 // RFC4754
// also RFC 7427 - Signature Authentication in IKEv2

// authenticates peer
func authenticate(msg *Message, initB []byte, idP *protocol.IdPayload, tkm *Tkm, idRemote Identities) bool {
	authP := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		psk := &psk{tkm}
		return psk.Verify(initB, idP, authP.Data, idRemote)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE:
		rsaCert := &RsaCert{tkm}
		certP := msg.Payloads.Get(protocol.PayloadTypeCERT)
		return rsaCert.Verify(certP, initB, idP, authP.Data)
	}
	log.Errorf("Ike Auth failed: auth method not supported: %d", authP.AuthMethod)
	return false
}
