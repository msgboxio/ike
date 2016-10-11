package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/protocol"
)

// CertAuthenticator is an Authenticator
type CertAuthenticator struct {
	tkm          *Tkm
	forInitiator bool
	identity     Identity
	authMethod   protocol.AuthMethod

	userCertificate *x509.Certificate
}

func (r *CertAuthenticator) Identity() Identity {
	return r.identity
}

func (r *CertAuthenticator) AuthMethod() protocol.AuthMethod {
	return r.authMethod
}

func (r *CertAuthenticator) Sign(initB []byte, idP *protocol.IdPayload) ([]byte, error) {
	certId, ok := r.identity.(*CertIdentity)
	if !ok {
		// should never happen
		panic("Logic Error")
	}
	// certificate is not required to sign
	// it is transferred to peer, and hopefully signature algos are compatible
	if certId.Certificate == nil {
		return nil, fmt.Errorf("missing certificate")
	}
	if certId.PrivateKey == nil {
		return nil, fmt.Errorf("missing private key")
	}
	signed := r.tkm.SignB(initB, idP.Encode(), r.forInitiator)
	return Sign(certId.Certificate.SignatureAlgorithm, r.AuthMethod(), signed, certId.PrivateKey)
}

func (r *CertAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte) error {
	certId, ok := r.identity.(*CertIdentity)
	if !ok {
		// should never happen
		panic("logic error")
	}
	if r.userCertificate == nil {
		return errors.New("Ike Auth failed: missing Certificate")
	}
	// ensure key used to compute a digital signature belongs to the name in the ID payload
	if bytes.Compare(idP.Data, r.userCertificate.RawSubject) != 0 {
		return fmt.Errorf("Ike Auth failed: incorrect id in certificate: %s",
			hex.Dump(r.userCertificate.RawSubject))
	}
	// TODO - ensure that the ID is authorized
	// Verify validity of certificate
	opts := x509.VerifyOptions{
		Roots: certId.Roots,
	}
	if _, err := r.userCertificate.Verify(opts); err != nil {
		return fmt.Errorf("Ike Auth failed: unable to verify certificate: %s",
			err)
	}
	signed := r.tkm.SignB(initB, idP.Encode(), !r.forInitiator)
	return VerifySignature(r.AuthMethod(), signed, authData, r.userCertificate)
}

func (r *CertAuthenticator) SetUserCertificate(cert *x509.Certificate) {
	r.userCertificate = cert
}
