package ike

import (
	"crypto/x509"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// CertAuthenticator is an Authenticator
type CertAuthenticator struct {
	tkm             *Tkm
	forInitiator    bool
	identity        Identity
	authMethod      protocol.AuthMethod
	userCertificate *x509.Certificate

	log *logrus.Logger
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
		return nil, errors.Errorf("missing certificate")
	}
	if certId.PrivateKey == nil {
		return nil, errors.Errorf("missing private key")
	}
	r.log.Infof("Ike Auth: OUR CERT: %+v", FormatCert(certId.Certificate))
	signed := r.tkm.SignB(initB, idP.Encode(), r.forInitiator)
	return Sign(certId.Certificate.SignatureAlgorithm, r.AuthMethod(), signed, certId.PrivateKey, r.log)
}

func (r *CertAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte) error {
	if r.userCertificate == nil {
		return errors.New("missing Certificate")
	}
	signed := r.tkm.SignB(initB, idP.Encode(), !r.forInitiator)
	return verifySignature(r.AuthMethod(), signed, authData, r.userCertificate, r.log)
}

func (r *CertAuthenticator) SetUserCertificate(cert *x509.Certificate) {
	r.userCertificate = cert
}
