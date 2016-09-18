package ike

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type RsaSig struct {
	*Tkm
	ourPrivate *rsa.PrivateKey
	peerPublic *rsa.PublicKey
}

func (r *RsaSig) Sign(initB []byte, id *protocol.IdPayload) []byte {
	rng := rand.Reader
	hash := sha1.Sum(r.Tkm.SignB(initB, id.Encode(), r.Tkm.isInitiator))
	signature, err := rsa.SignPKCS1v15(rng, r.ourPrivate, crypto.SHA1, hash[:])
	if err == nil {
		return signature
	}
	log.Errorf("Ike Auth failed: error while signing: %s", err)
	return nil
}

func (r *RsaSig) Verify(initB []byte, id *protocol.IdPayload, authData []byte) bool {
	// TODO - sha1 assumed when verifying signatures
	hash := sha1.Sum(r.Tkm.SignB(initB, id.Encode(), !r.Tkm.isInitiator))
	err := rsa.VerifyPKCS1v15(r.peerPublic, crypto.SHA1, hash[:], authData)
	if err == nil {
		return true
	}
	log.Errorf("Ike Auth failed: signature could not be verified: %s", err)
	return false
}
