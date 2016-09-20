package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

// psk implemments Authenticator interface
type PskAuthenticator struct {
	*Tkm
}

func (psk *PskAuthenticator) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE
}

// so signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// authB = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignB)
func (psk *PskAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, idLocal Identity) []byte {
	secret := idLocal.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		// could this be a security risk
		log.Infof("No Secret for %s", string(idP.Data))
	}
	signB := psk.Tkm.SignB(initB, idP.Encode(), psk.Tkm.isInitiator)
	if log.V(2) {
		log.Infof("Ike PSK Auth as %s", string(idP.Data))
	}
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.Tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
}

func (psk *PskAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) bool {
	secret := idRemote.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		// CAREFUL here - this could be a potential security risk
		log.Errorf("Ike PSK Auth of %s failed: No Secret is available", string(idP.Data))
		return false
	}
	signB := psk.Tkm.SignB(initB, idP.Encode(), !psk.Tkm.isInitiator)
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.Tkm.suite.Prf
	signedB := prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
	// compare
	if hmac.Equal(signedB, authData) {
		if log.V(2) {
			log.Infof("Ike PSK Auth of %s successful", string(idP.Data))
		}
		return true
	}
	if log.V(2) {
		log.Errorf("Ike PSK Auth of %s failed: \n%s vs \n%s", string(idP.Data), hex.Dump(signedB), hex.Dump(authData))
	}
	return false
}
