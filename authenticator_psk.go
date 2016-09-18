package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type psk struct {
	*Tkm
	id Identities
}

func (psk *psk) IdType() protocol.IdType {
	return psk.id.IdType()
}

func (psk *psk) Id() []byte {
	return psk.id.ForAuthentication(psk.IdType())
}

func (psk *psk) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE
}

// so signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// authB = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignB)
func (psk *psk) Sign(initB []byte, id *protocol.IdPayload, flag protocol.IkeFlags) []byte {
	secret := psk.id.AuthData(id.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		// TODO - this is a potential security risk
		log.Infof("No Secret for %s", string(id.Data))
	}
	signB := psk.Tkm.SignB(initB, id.Encode(), flag.IsInitiator())
	if log.V(2) {
		log.Infof("Ike PSK Auth as %s", string(id.Data))
	}
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.Tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
}

func (psk *psk) Verify(initB []byte, id *protocol.IdPayload, flag protocol.IkeFlags, authData []byte) bool {
	secret := psk.id.AuthData(id.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		// CAREFUL here - this could be a potential security risk
		log.Errorf("Ike PSK Auth of %s failed: No Secret is available", string(id.Data))
		return false
	}
	signB := psk.Tkm.SignB(initB, id.Encode(), flag.IsInitiator())
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.Tkm.suite.Prf
	signedB := prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
	// compare
	if hmac.Equal(signedB, authData) {
		if log.V(2) {
			log.Infof("Ike PSK Auth of %s successful", string(id.Data))
		}
		return true
	}
	if log.V(2) {
		log.Errorf("Ike PSK Auth of %s failed: \n%s vs \n%s", string(id.Data), hex.Dump(signedB), hex.Dump(authData))
	}
	return false
}
