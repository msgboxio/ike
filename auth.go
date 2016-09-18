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

// authenticates Initiator
func authenticateI(msg *Message, initIb []byte, tkm *Tkm, id Identities) bool {
	// id payload
	idI := msg.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	// auth payload
	authIp := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	switch authIp.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		psk := &psk{tkm, id}
		return psk.Verify(initIb, idI, protocol.INITIATOR, authIp.Data)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE:
		rsaCert := &RsaCert{tkm}
		certP := msg.Payloads.Get(protocol.PayloadTypeCERT)
		return rsaCert.Verify(certP, initIb, idI, protocol.INITIATOR, authIp.Data)
	}
	log.Errorf("Ike Auth failed: auth method not supported: %d", authIp.AuthMethod)
	return false
}

// peer is responder
func authenticateR(msg *Message, initRb []byte, tkm *Tkm, id Identities) bool {
	// id payload
	idR := msg.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	// auth payload
	authRp := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	// expected auth
	switch authRp.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		psk := &psk{tkm, id}
		return psk.Verify(initRb, idR, protocol.RESPONSE, authRp.Data)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE:
		rsaCert := &RsaCert{tkm}
		certP := msg.Payloads.Get(protocol.PayloadTypeCERT)
		return rsaCert.Verify(certP, initRb, idR, protocol.RESPONSE, authRp.Data)
	}
	log.Errorf("Ike Auth failed: auth method not supported: %v", authRp.AuthMethod)
	return false
}
