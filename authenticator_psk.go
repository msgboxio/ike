package ike

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

var _Keypad = []byte("Key Pad for IKEv2")

// PskAuthenticator is an Authenticator
type PskAuthenticator struct {
	tkm *Tkm
}

func (psk *PskAuthenticator) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE
}

// signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// authB = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignB)
func (psk *PskAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, idLocal Identity) ([]byte, error) {
	secret := idLocal.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		return nil, fmt.Errorf("No Secret for %s", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), psk.tkm.isInitiator)
	if log.V(2) {
		log.Infof("Ike PSK Auth as %s", string(idP.Data))
	}
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length], nil
}

func (psk *PskAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) error {
	secret := idRemote.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		return fmt.Errorf("Ike PSK Auth of %s failed: No Secret is available", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), !psk.tkm.isInitiator)
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.tkm.suite.Prf
	signedB := prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length]
	// compare
	if hmac.Equal(signedB, authData) {
		if log.V(2) {
			log.Infof("Ike PSK Auth of %s successful", string(idP.Data))
		}
		return nil
	}
	return fmt.Errorf("Ike PSK Auth of %s failed: \n%s vs \n%s", string(idP.Data), hex.Dump(signedB), hex.Dump(authData))
}
