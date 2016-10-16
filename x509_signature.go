package ike

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/pkg/errors"
)

var asnCertAuthTypes = map[string]x509.SignatureAlgorithm{}
var signatureAlgorithmToAsn1 = map[x509.SignatureAlgorithm][]byte{}

// asn1 objects from rfc7427
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

func init() {
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
	for k, v := range _asnCertAuthTypes {
		d, _ := hex.DecodeString(k)
		asnCertAuthTypes[string(d)] = v
		signatureAlgorithmToAsn1[v] = d
	}
}

func VerifySignature(authMethod protocol.AuthMethod, signed, signature []byte, cert *x509.Certificate) error {
	// if using plain rsa signature, verify using SHA1
	if authMethod == protocol.AUTH_RSA_DIGITAL_SIGNATURE {
		return checkSignature(signed, signature, x509.SHA1WithRSA, cert)
	}
	// further parse signature to extract hash & signature algorithm
	sigAuth := &protocol.SignatureAuth{}
	if err := sigAuth.Decode(signature); err != nil {
		return err
	}
	// check if specified signature algorithm is available
	if method, ok := asnCertAuthTypes[string(sigAuth.Asn1Data)]; ok {
		if err := checkSignature(signed, sigAuth.Signature, method, cert); err != nil {
			return errors.Errorf("Ike Auth failed: with method %s, %s", method, err)
		}
	} else {
		return errors.Errorf("Ike Auth failed: auth method not supported:\n%s", hex.Dump(sigAuth.Asn1Data))
	}
	return nil
}

func checkSignature(signed, signature []byte, algorithm x509.SignatureAlgorithm, cert *x509.Certificate) error {
	log.V(1).Infof("Checking SignatureAlgorithm %v, chosen SignatureAlgorithm %v",
		cert.SignatureAlgorithm, algorithm)
	if err := cert.CheckSignature(algorithm, signed, signature); err != nil {
		return err
	}
	if log.V(2) {
		log.Infof("Ike CERT Auth of %+v successful", cert.Subject)
	}
	return nil
}

func Sign(algo x509.SignatureAlgorithm, authMethod protocol.AuthMethod, signed []byte, private crypto.PrivateKey) ([]byte, error) {
	// if using a plain old signature, this is all we need
	if authMethod == protocol.AUTH_RSA_DIGITAL_SIGNATURE {
		return sign(x509.SHA1WithRSA, signed, private)
	}
	signature, err := sign(algo, signed, private)
	if err != nil {
		return nil, err
	}
	// encode rfc7427 signature
	sigAuth := &protocol.SignatureAuth{
		Asn1Data:  signatureAlgorithmToAsn1[algo],
		Signature: signature,
	}
	return sigAuth.Encode(), nil
}

func sign(algo x509.SignatureAlgorithm, signed []byte, private crypto.PrivateKey) (signature []byte, err error) {
	log.V(1).Infof("Signing Using SignatureAlgorithm: %v", algo)
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

	priv, ok := private.(crypto.Signer)
	if !ok {
		return nil, errors.New("certificate private key does not implement crypto.Signer")
	}
	// TODO - should we check if the key & cert match ??
	return priv.Sign(rand.Reader, digest, hashType)
}
