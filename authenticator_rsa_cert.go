package ike

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type RsaCert struct {
	tkm *Tkm
}

func (r *RsaCert) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_RSA_DIGITAL_SIGNATURE
}
func (r *RsaCert) Sign([]byte, *protocol.IdPayload, Identity) []byte {
	return nil
}
func (r *RsaCert) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) bool {
	certId, ok := idRemote.(*RsaCertIdentity)
	if !ok {
		// should never happen
		return false
	}
	if certId.Certificate == nil {
		return false
	}
	x509Cert := certId.Certificate
	// ensure key used to compute a digital signature belongs to the name in the ID payload
	if bytes.Compare(idP.Data, x509Cert.RawSubject) != 0 {
		log.Errorf("Ike Auth failed: incorrect id in certificate: %s",
			hex.Dump(x509Cert.RawSubject))
		return false
	}
	// TODO - ensure that the ID is authorized
	// use the public key in the cert to verify auth data
	opts := x509.VerifyOptions{
		Roots: certId.Roots,
	}
	if _, err := x509Cert.Verify(opts); err != nil {
		log.Errorf("failed to verify certificate: %s", err)
		return false
	}
	log.Info("verified certificate")
	rsaPublic, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Errorf("Ike Auth failed: incorrect public key type")
		return false
	}
	rsaSig := &RsaSig{
		Tkm:        r.tkm,
		peerPublic: rsaPublic,
	}
	if rsaSig.Verify(initB, idP, authData) {
		if log.V(2) {
			log.Infof("Ike CERT Auth of %+v successful", x509Cert.Subject)
		}
		return true
	}
	return false
}
