package ike

import (
	"bytes"
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
	auth := tkm.Auth(signed1, idI, authIp.AuthMethod, protocol.INITIATOR)
	// compare
	if bytes.Equal(auth, authIp.Data) {
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
	auth := tkm.Auth(signed1, idR, authRp.AuthMethod, protocol.RESPONSE)
	// compare
	if bytes.Equal(auth, authRp.Data) {
		return true
	} else if log.V(3) {
		log.Errorf("Ike Auth failed: \n%s vs \n%s", hex.Dump(auth), hex.Dump(authRp.Data))
	}
	return false
}
