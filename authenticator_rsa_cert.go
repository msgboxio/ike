package ike

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

// RsaCert is an Authenticator
type RsaCert struct {
	tkm  *Tkm
	cert *x509.Certificate
}

func (r *RsaCert) AuthMethod() protocol.AuthMethod {
	return protocol.AUTH_RSA_DIGITAL_SIGNATURE
}

func (r *RsaCert) Sign(initB []byte, idP *protocol.IdPayload, idLocal Identity) ([]byte, error) {
	certId, ok := idLocal.(*RsaCertIdentity)
	if !ok {
		// should never happen
		panic("Logic Error")
	}
	if certId.Certificate == nil {
		return nil, fmt.Errorf("missing certificate")
	}
	if certId.PrivateKey == nil {
		return nil, fmt.Errorf("missing private key")
	}
	rsaPublic, ok := certId.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("incorrect public key type")
	}
	rsaSig := &RsaSig{
		Tkm:        r.tkm,
		peerPublic: rsaPublic,
		ourPrivate: certId.PrivateKey,
	}
	return rsaSig.Sign(initB, idP), nil
}

func (r *RsaCert) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, idRemote Identity) error {
	certId, ok := idRemote.(*RsaCertIdentity)
	if !ok {
		// should never happen
		panic("logic error")
	}
	if r.cert == nil {
		return errors.New("Ike Auth failed: missing Certificate")
	}
	x509Cert := r.cert
	// ensure key used to compute a digital signature belongs to the name in the ID payload
	if bytes.Compare(idP.Data, x509Cert.RawSubject) != 0 {
		return fmt.Errorf("Ike Auth failed: incorrect id in certificate: %s",
			hex.Dump(x509Cert.RawSubject))
	}
	// TODO - ensure that the ID is authorized
	// Verify validity of certificate
	opts := x509.VerifyOptions{
		Roots: certId.Roots,
	}
	if _, err := x509Cert.Verify(opts); err != nil {
		return fmt.Errorf("Ike Auth failed: unable to verify certificate: %s",
			err)
	}
	log.Info("verified certificate")
	// use the public key in the cert to verify auth data
	rsaPublic, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("Ike Auth failed: incorrect public key type: %v",
			x509Cert.PublicKeyAlgorithm)
	}
	rsaSig := &RsaSig{
		Tkm:        r.tkm,
		peerPublic: rsaPublic,
	}
	if !rsaSig.Verify(initB, idP, authData) {
		return errors.New("Ike Auth failed: unable to signature")
	}
	if log.V(2) {
		log.Infof("Ike CERT Auth of %+v successful", x509Cert.Subject)
	}
	return nil
}

func (r *RsaCert) SetUserCertificate(cert *x509.Certificate) {
	r.cert = cert
}
