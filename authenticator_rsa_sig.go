package ike

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type RsaSig struct {
	*Tkm
	ourPrivate    *rsa.PrivateKey
	peerPublic    *rsa.PublicKey
	signatureHash hash.Hash
	hashType      crypto.Hash
}

func (r *RsaSig) Sign(initB []byte, id *protocol.IdPayload) []byte {
	r.signatureHash.Write(r.Tkm.SignB(initB, id.Encode(), r.Tkm.isInitiator))
	hash := r.signatureHash.Sum(nil)[:r.signatureHash.Size()]
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.ourPrivate, r.hashType, hash)
	if err != nil {
		log.Errorf("Ike Auth failed: error while signing: %s", err)
		return nil
	}
	return signature
}

func (r *RsaSig) Verify(initB []byte, id *protocol.IdPayload, signature []byte) error {
	r.signatureHash.Write(r.Tkm.SignB(initB, id.Encode(), !r.Tkm.isInitiator))
	hash := r.signatureHash.Sum(nil)[:r.signatureHash.Size()]
	// TODO - padding method is also pre-configured
	if err := rsa.VerifyPKCS1v15(r.peerPublic, r.hashType, hash, signature); err != nil {
		return fmt.Errorf("Ike Auth failed: %s", err)
	}
	return nil
}
