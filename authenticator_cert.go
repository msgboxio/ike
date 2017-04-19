package ike

import (
	"crypto/x509"

	"github.com/go-kit/kit/log"
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
}

var _ Authenticator = (*CertAuthenticator)(nil)

func (o *CertAuthenticator) Identity() Identity {
	return o.identity
}

func (o *CertAuthenticator) AuthMethod() protocol.AuthMethod {
	return o.authMethod
}

func (o *CertAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, logger log.Logger) ([]byte, error) {
	certID, ok := o.identity.(*CertIdentity)
	if !ok {
		// should never happen
		panic("Logic Error")
	}
	// certificate is not required to sign
	// it is transferred to peer, and hopefully signature algos are compatible
	if certID.Certificate == nil {
		return nil, errors.Errorf("missing certificate")
	}
	if certID.PrivateKey == nil {
		return nil, errors.Errorf("missing private key")
	}
	cert := FormatCert(certID.Certificate)
	logger.Log("Auth", "OUR", "cert", cert.String())
	signed := o.tkm.SignB(initB, idP.Encode(), o.forInitiator)
	return CreateSignature(certID.Certificate.SignatureAlgorithm, o.AuthMethod(), signed, certID.PrivateKey, logger)
}

func (o *CertAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, logger log.Logger) error {
	if o.userCertificate == nil {
		return errors.New("missing Certificate")
	}
	signed := o.tkm.SignB(initB, idP.Encode(), !o.forInitiator)
	return VerifySignature(o.AuthMethod(), signed, authData, o.userCertificate, logger)
}

func (o *CertAuthenticator) SetUserCertificate(cert *x509.Certificate) {
	o.userCertificate = cert
}
