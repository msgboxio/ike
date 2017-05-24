package ike

import (
	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// Authenticator is used to authenticate & create AUTH payloads
type Authenticator interface {
	Identity() Identity
	Sign([]byte, *protocol.IdPayload, log.Logger) ([]byte, error)
	Verify(initB []byte, idP *protocol.IdPayload, authMethod protocol.AuthMethod, authData []byte, inbandData interface{}, logger log.Logger) error
}

func NewAuthenticator(id Identity, tkm *Tkm, forInitiator, rfc7427Signatures bool) Authenticator {
	switch id.(type) {
	case *PskIdentities:
		return &proxyAuthenticator{
			realAuth: &PskAuthenticator{
				tkm:          tkm,
				forInitiator: forInitiator,
				identity:     id,
			}}
	case *CertIdentity:
		return &proxyAuthenticator{
			realAuth: &CertAuthenticator{
				tkm:               tkm,
				forInitiator:      forInitiator,
				identity:          id,
				rfc7427Signatures: rfc7427Signatures,
			}}
	default:
		panic("no authenticator found for id: " + id.IdType().String())
	}
}

// build a proxy authenticator
type proxyAuthenticator struct {
	realAuth Authenticator
}

func (p *proxyAuthenticator) Identity() Identity {
	return p.realAuth.Identity()
}
func (p *proxyAuthenticator) Sign(initB []byte, idP *protocol.IdPayload, logger log.Logger) ([]byte, error) {
	return p.realAuth.Sign(initB, idP, logger)
}
func (p *proxyAuthenticator) Verify(initB []byte, idP *protocol.IdPayload, authMethod protocol.AuthMethod, authData []byte, inbandData interface{}, logger log.Logger) error {
	switch authMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		// find authenticator
		pskAuth, ok := p.realAuth.(*PskAuthenticator)
		if !ok {
			return errors.New("PreShared Key authentication is required")
		}
		return pskAuth.Verify(initB, idP, authMethod, authData, nil, logger)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		// find authenticator
		certAuth, ok := p.realAuth.(*CertAuthenticator)
		if !ok {
			return errors.New("Certificate authentication is required")
		}
		return certAuth.Verify(initB, idP, authMethod, authData, inbandData, logger)
	default:
		return errors.Errorf("Authentication method is not supported: %s", authMethod)
	}
}
