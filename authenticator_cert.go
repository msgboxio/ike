package ike

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

var asnCertAuthTypes = map[string]x509.SignatureAlgorithm{}
var signatureAlgorithmToAsn1 = map[x509.SignatureAlgorithm]string{}

// asn1 objects
var (
	AsnSHA1WithRSA      = "300d06092a864886f70d0101050500"
	AsnSHA256WithRSA    = "300d06092a864886f70d01010b0500"
	AsnSHA384WithRSA    = "300d06092a864886f70d01010c0500"
	AsnSHA512WithRSA    = "300d06092a864886f70d01010d0500"
	AsnDSAWithSHA1      = "300906072a8648ce380403"
	AsnDSAWithSHA256    = "300b0609608648016503040302"
	AsnECDSAWithSHA1    = "300906072a8648ce3d0401"
	AsnECDSAWithSHA256  = "300a06082a8648ce3d040302"
	AsnECDSAWithSHA384  = "300a06082a8648ce3d040303"
	AsnECDSAWithSHA512  = "300a06082a8648ce3d040304"
	AsnRsaSsaPss        = "300d06092a864886f70d01010a3000"
	AsnRsaSsaPssDefault = "303e06092a864886f70d01010a3031a00b300906052b0e03021a0500a118301606092a864886f70d010108300906052b0e03021a0500a203020114a303020101"
	AsnSHA256WithRSAPSS = "304606092a864886f70d01010a3039a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120a303020101"
)

var _asnCertAuthTypes = map[string]x509.SignatureAlgorithm{
	AsnSHA1WithRSA:     x509.SHA1WithRSA,
	AsnSHA256WithRSA:   x509.SHA256WithRSA,
	AsnSHA384WithRSA:   x509.SHA384WithRSA,
	AsnSHA512WithRSA:   x509.SHA512WithRSA,
	AsnDSAWithSHA1:     x509.DSAWithSHA1,
	AsnDSAWithSHA256:   x509.DSAWithSHA256,
	AsnECDSAWithSHA1:   x509.ECDSAWithSHA1,
	AsnECDSAWithSHA256: x509.ECDSAWithSHA256,
	AsnECDSAWithSHA384: x509.ECDSAWithSHA384,
	AsnECDSAWithSHA512: x509.ECDSAWithSHA512,
	// AsnRsaSsaPss:       nil,
	// AsnRsaSsaPssDefault:        nil,
	// AsnRsaSsaPssSha256: x509.SHA256WithRSAPSS, // go 1.8
}

func init() {
	for k, v := range _asnCertAuthTypes {
		d, _ := hex.DecodeString(k)
		asnCertAuthTypes[string(d)] = v
		signatureAlgorithmToAsn1[v] = string(d)
	}
}

// CertAuthenticator is an Authenticator
type CertAuthenticator struct {
	tkm          *Tkm
	forInitiator bool
	identity     Identity
	authMethod   protocol.AuthMethod

	userCertificate    *x509.Certificate
	signatureAlgorithm x509.SignatureAlgorithm
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
	log.V(1).Infof("Signing SignatureAlgorithm %v, chosen SignatureAlgorithm %v",
		certId.Certificate.SignatureAlgorithm, r.signatureAlgorithm)
	signed := r.tkm.SignB(initB, idP.Encode(), r.forInitiator)
	return sign(r.signatureAlgorithm, signed, certId.PrivateKey)
}

func sign(algo x509.SignatureAlgorithm, signed []byte, private crypto.PrivateKey) (signature []byte, err error) {
	var hashType crypto.Hash

	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA /*x509.SHA256WithRSAPSS*/, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA /*x509.SHA384WithRSAPSS,*/, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA /*x509.SHA512WithRSAPSS,*/, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		return nil, x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	// TODO - extend this for other key types
	switch pvt := private.(type) {
	case *rsa.PrivateKey:
		// if algo.isRSAPSS() {
		// return rsa.VerifyPSS(pub, hashType, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		// } else {
		return rsa.SignPKCS1v15(rand.Reader, pvt, hashType, digest)
		// }
	}
	return nil, x509.ErrUnsupportedAlgorithm
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
	log.V(1).Infof("Checking SignatureAlgorithm %v, chosen SignatureAlgorithm %v",
		r.userCertificate.SignatureAlgorithm, r.signatureAlgorithm)
	signed := r.tkm.SignB(initB, idP.Encode(), !r.forInitiator)
	if err := r.userCertificate.CheckSignature(r.signatureAlgorithm, signed, authData); err != nil {
		return err
	}
	if log.V(2) {
		log.Infof("Ike CERT Auth of %+v successful", r.userCertificate.Subject)
	}
	return nil
}

func (r *CertAuthenticator) SetUserCertificate(cert *x509.Certificate) {
	r.userCertificate = cert
}
