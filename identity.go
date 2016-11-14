package ike

import (
	"crypto"
	"crypto/x509"

	"github.com/msgboxio/ike/protocol"
)

type Identity interface {
	IdType() protocol.IdType
	Id() []byte
	AuthData(id []byte, method protocol.AuthMethod) []byte
}

type PskIdentities struct {
	Ids     map[string][]byte
	Primary string
}

func (psk *PskIdentities) IdType() protocol.IdType {
	return protocol.ID_RFC822_ADDR
}

func (psk *PskIdentities) Id() []byte {
	return []byte(psk.Primary)
}

func (psk *PskIdentities) AuthData(id []byte, method protocol.AuthMethod) []byte {
	if method != protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE {
		return nil
	}
	if d, ok := psk.Ids[string(id)]; ok {
		return d
	}
	return nil
}

type CertIdentity struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	Roots       *x509.CertPool
	Name        string
}

func (c *CertIdentity) IdType() protocol.IdType {
	return protocol.ID_DER_ASN1_DN
}

func (c *CertIdentity) Id() []byte {
	return c.Certificate.RawSubject
}

func (c *CertIdentity) AuthData(id []byte, method protocol.AuthMethod) []byte {
	return nil
}
