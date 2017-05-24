package ike

import (
	"crypto/hmac"
	"fmt"

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

// signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// authB = prf( prf(Shared Secret, "Key Pad for IKEv2"), SignB)
func (psk *PskAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, logger log.Logger) ([]byte, error) {
	secret := psk.identity.AuthData(idP.Data)
	if secret == nil {
		return nil, errors.Errorf("No Secret for %s", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), psk.forInitiator)
	logger.Log("AUTH", fmt.Sprintf("OUR_KEY[%s]", string(idP.Data)))
	// NOTE : tkm.Auth always uses the hash negotiated for prf
	prf := psk.tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length], nil
}

func (psk *PskAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authMethod protocol.AuthMethod, authData []byte, inbandData interface{}, logger log.Logger) error {
	logger.Log("AUTH", fmt.Sprintf("PEER_KEY[%s]", string(idP.Data)))
	secret := psk.identity.AuthData(idP.Data)
	if secret == nil {
		return errors.Errorf("Ike PSK Auth for: %s failed, No Secret", string(idP.Data))
	}
	signB := psk.tkm.SignB(initB, idP.Encode(), !psk.forInitiator)
	// NOTE : tkm.Auth always uses the hash negotiated for prf
	prf := psk.tkm.suite.Prf
	signedB := prf.Apply(prf.Apply(secret, _Keypad), signB)[:prf.Length]
	// compare
	if !hmac.Equal(signedB, authData) {
		return errors.Errorf("Ike PSK Auth failed for: %s", string(idP.Data))
	}
	return nil
}
