package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

// TODO:
// currently support for signature authenticaiton is limited to
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
// AUTH_ECDSA_256                         AuthMethod = 9  // RFC4754
// AUTH_ECDSA_384                         AuthMethod = 10 // RFC4754
// AUTH_ECDSA_521                         AuthMethod = 11 // RFC4754

type Authenticator interface {
	IdType() protocol.IdType
	Id() []byte
	AuthMethod() protocol.AuthMethod
	Sign([]byte, *protocol.IdPayload, protocol.IkeFlags) []byte
}

type psk struct{ tkm *Tkm }

func (psk *psk) IdType() protocol.IdType {
	return psk.tkm.ids.IdType()
}

func (psk *psk) Id() []byte {
	return psk.tkm.ids.ForAuthentication(psk.IdType())
}

func (psk *psk) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE
}

func (psk *psk) Sign(signed1 []byte, id *protocol.IdPayload, flag protocol.IkeFlags) []byte {
	signB := psk.tkm.signB(signed1, id, flag)
	secret := psk.tkm.ids.AuthData(id.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	prf := psk.tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
}

func authenticateI(msg *Message, initIb []byte, tkm *Tkm) bool {
	// id payload
	idI := msg.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Initiator ID:%s", string(idI.Data))
	// intiators's signed octet
	// initI | Nr | prf(sk_pi | IDi )
	// first part of signed bytes
	signed1 := append(initIb, tkm.Nr.Bytes()...)
	// auth payload
	authIp := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	// expected auth
	psk := &psk{tkm}
	if psk.AuthMethod() != authIp.AuthMethod {
		log.Errorf("Ike Auth failed: auth method not supported: %d", authIp.AuthMethod)
		return false
	}
	auth := psk.Sign(signed1, idI, protocol.INITIATOR)
	// compare
	if hmac.Equal(auth, authIp.Data) {
		return true
	} else if log.V(3) {
		log.Errorf("Ike Auth failed: \n%s vs \n%s", hex.Dump(auth), hex.Dump(authIp.Data))
	}
	return false
}

func authenticateR(msg *Message, initRb []byte, tkm *Tkm) bool {
	// id payload
	idR := msg.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Responder ID:%s", string(idR.Data))
	// responders's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	signed1 := append(initRb, tkm.Ni.Bytes()...)
	// auth payload
	authRp := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	// expected auth
	psk := &psk{tkm}
	if psk.AuthMethod() != authRp.AuthMethod {
		log.Errorf("Ike Auth failed: auth method not supported: %d", authRp.AuthMethod)
		return false
	}
	auth := psk.Sign(signed1, idR, protocol.INITIATOR)
	// compare
	if hmac.Equal(auth, authRp.Data) {
		return true
	} else if log.V(3) {
		log.Errorf("Ike Auth failed: \n%s vs \n%s", hex.Dump(auth), hex.Dump(authRp.Data))
	}
	return false
}
