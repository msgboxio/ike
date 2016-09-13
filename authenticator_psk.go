package ike

import (
	"crypto/hmac"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

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
	// TODO : tkm.Auth always uses the hash negotiated with prf
	prf := psk.tkm.suite.Prf
	return prf.Apply(prf.Apply(secret, []byte("Key Pad for IKEv2")), signB)[:prf.Length]
}

// responder's signed octet
// initR | Ni | prf(sk_pr | IDr )
// intiators's signed octet
// initI | Nr | prf(sk_pi | IDi )
func (psk *psk) Verify(signed1 []byte, id *protocol.IdPayload, flag protocol.IkeFlags, authData []byte) bool {
	auth := psk.Sign(signed1, id, flag)
	// compare
	if hmac.Equal(auth, authData) {
		if log.V(2) {
			log.Infof("Ike PSK Auth of %s successful", string(id.Data))
		}
		return true
	}
	if log.V(2) {
		log.Errorf("Ike PSK Auth of %s failed: \n%s vs \n%s", string(id.Data), hex.Dump(auth), hex.Dump(authData))
	}
	return false
}
