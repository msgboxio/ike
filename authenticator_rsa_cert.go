package ike

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type RsaCert struct {
	tkm *Tkm
}

func (r *RsaCert) Verify(certP protocol.Payload, signed1 []byte, id *protocol.IdPayload, flag protocol.IkeFlags, authData []byte) bool {
	if certP == nil {
		log.Errorf("Ike Auth failed: certificate is required")
		return false
	}
	cert := certP.(*protocol.CertPayload)
	if cert.CertEncodingType != protocol.X_509_CERTIFICATE_SIGNATURE {
		log.Errorf("Ike Auth failed: cert encoding not supported: %v", cert.CertEncodingType)
		return false
	}
	// cert.data is DER-encoded X.509 certificate
	x509Cert, err := x509.ParseCertificate(cert.Data)
	if err != nil {
		log.Errorf("Ike Auth failed: uanble to parse cert: %s", err)
		return false
	}
	// ensure key used to compute a digital signature belongs to the name in the ID payload
	if bytes.Compare(id.Data, x509Cert.RawSubject) != 0 {
		log.Errorf("Ike Auth failed: incorrect id in certificate: %s", err)
		return false
	}
	// TODO - ensure that the ID is authorized
	// use the public key in the cert to verify auth data
	opts := x509.VerifyOptions{
		Roots: r.tkm.Roots,
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
	if rsaSig.Verify(signed1, id, flag, authData) {
		if log.V(2) {
			log.Infof("Ike CERT Auth of %+v successful", x509Cert.Subject)
		}
		return true
	}
	return false
}
