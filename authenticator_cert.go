package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// CertAuthenticator is an Authenticator
type CertAuthenticator struct {
	tkm               *Tkm
	forInitiator      bool
	identity          Identity
	rfc7427Signatures bool
}

// this is an Authenticator
var _ Authenticator = (*CertAuthenticator)(nil)

func (o *CertAuthenticator) Identity() Identity {
	return o.identity
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
	logger.Log("AUTH", fmt.Sprintf("OUR_CERT[%s]", cert.String()))
	signed := o.tkm.SignB(initB, idP.Encode(), o.forInitiator)
	// try and use the configured method
	authMethod := certID.AuthMethod()
	if !o.rfc7427Signatures {
		authMethod = protocol.AUTH_RSA_DIGITAL_SIGNATURE
	}
	return CreateSignature(certID.Certificate.SignatureAlgorithm, authMethod, signed, certID.PrivateKey, logger)
}

func (o *CertAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authData []byte, inbandData interface{}, logger log.Logger) error {
	chain, ok := inbandData.([]*x509.Certificate)
	if !ok {
		// should never happen
		panic("logic error")
	}
	// chain will not be empty
	cert := FormatCert(chain[0])
	logger.Log("AUTH", fmt.Sprintf("PEER_CERT[%s]", cert.String()))
	// ensure key used to compute a digital signature belongs to the name in the ID payload
	if bytes.Compare(idP.Data, chain[0].RawSubject) != 0 {
		return errors.Errorf("Incorrect id in certificate: %s", hex.Dump(chain[0].RawSubject))
	}
	// find identity
	certID, ok := o.identity.(*CertIdentity)
	if !ok {
		// should never happen
		panic("logic error")
	}
	// Verify validity of certificate
	opts := x509.VerifyOptions{
		Roots: certID.Roots,
	}
	if _, err := chain[0].Verify(opts); err != nil {
		return errors.Wrap(err, "Unable to verify certificate")
	}
	// ensure that certificate is for authorized ID: check in subject & altname
	// TODO - is this reasonable?
	if !MatchNameFromCert(&cert, certID.Name) {
		return errors.Errorf("Certificate is not Authorized for Name: %s", certID.Name)
	}
	signed := o.tkm.SignB(initB, idP.Encode(), !o.forInitiator)
	// try and use the configured method
	authMethod := certID.AuthMethod()
	if !o.rfc7427Signatures {
		authMethod = protocol.AUTH_RSA_DIGITAL_SIGNATURE
	}
	return VerifySignature(authMethod, signed, authData, chain[0], logger)
}
