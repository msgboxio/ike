package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var _Keypad = []byte("Key Pad for IKEv2")

// PskAuthenticator is an Authenticator
type PskAuthenticator struct {
	tkm          *Tkm
	forInitiator bool
	identity     Identity
}

var _ Authenticator = (*PskAuthenticator)(nil)

func (psk *PskAuthenticator) Identity() Identity {
	return psk.identity
}

func (psk *PskAuthenticator) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE
}

// signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// authB = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignB)
func (psk *PskAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, logger log.Logger) ([]byte, error) {
	secret := psk.identity.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		return nil, errors.Errorf("No Secret for %s", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), psk.forInitiator)
	logger.Log("sign", "PSK", "id", string(idP.Data))
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length], nil
}

func (psk *PskAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, logger log.Logger) error {
	secret := psk.identity.AuthData(idP.Data, protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE)
	if secret == nil {
		return errors.Errorf("Ike PSK Auth for %s failed: No Secret is available", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), !psk.forInitiator)
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.tkm.suite.Prf
	signedB := prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length]
	// compare
	if !hmac.Equal(signedB, authData) {
		return errors.Errorf("Ike PSK Auth of %s failed: \n%s vs \n%s", string(idP.Data), hex.Dump(signedB), hex.Dump(authData))
	}
	return nil
}
