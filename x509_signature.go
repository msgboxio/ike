package ike

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var asnToCertAuth = map[string]x509.SignatureAlgorithm{}
var certAuthToAsn = map[x509.SignatureAlgorithm][]byte{}

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
		AsnSHA256WithRSAPSS: x509.SHA256WithRSAPSS, // go 1.8
	}
	for k, v := range _asnCertAuthTypes {
		d, _ := hex.DecodeString(k)
		asnToCertAuth[string(d)] = v
		certAuthToAsn[v] = d
	}
}

// VerifySignature using certificate & configured auth method
func VerifySignature(authMethod protocol.AuthMethod, signed, signature []byte, cert *x509.Certificate, log log.Logger) error {
	// if using plain rsa signature, verify using SHA1
	switch authMethod {
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DSS_DIGITAL_SIGNATURE:
		return cert.CheckSignature(x509.SHA1WithRSA, signed, signature)
		// not sure about this
		// case protocol.AUTH_ECDSA_256:
		// 	return cert.CheckSignature(x509.ECDSAWithSHA256, signed, signature)
		// case protocol.AUTH_ECDSA_384:
		// 	return cert.CheckSignature(x509.ECDSAWithSHA384, signed, signature)
		// case protocol.AUTH_ECDSA_521:
		// 	return cert.CheckSignature(x509.ECDSAWithSHA512, signed, signature)
	case protocol.AUTH_DIGITAL_SIGNATURE:
		return verifyAuthDigitalSig(authMethod, signed, signature, cert, log)
	default:
		return errors.Errorf("Authentication Method is not supported: %s", authMethod)
	}
}

func verifyAuthDigitalSig(authMethod protocol.AuthMethod, signed, signature []byte, cert *x509.Certificate, log log.Logger) error {
	// further parse signature to extract hash & signature algorithm
	sigAuth := &protocol.SignatureAuth{}
	if err := sigAuth.Decode(signature); err != nil {
		return err
	}
	// check if specified signature algorithm is available
	if algo, ok := asnToCertAuth[string(sigAuth.Asn1Data)]; ok {
		log.Log("asnSignatureAlgorithm", algo, "certSignatureAlgorithm", cert.SignatureAlgorithm)
		if err := cert.CheckSignature(algo, signed, sigAuth.Signature); err != nil {
			return errors.Errorf("Signature Check failed for method %s, %s", algo, err)
		}
	} else {
		return errors.Errorf("Signature type not supported:\n%s", hex.Dump(sigAuth.Asn1Data))
	}
	return nil
}

// CreateSignature signs request using private key & configured method
func CreateSignature(algo x509.SignatureAlgorithm, authMethod protocol.AuthMethod, signed []byte, private crypto.Signer, log log.Logger) ([]byte, error) {
	// if using a plain old signature, this is all we need
	switch authMethod {
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DSS_DIGITAL_SIGNATURE:
		return signData(x509.SHA1WithRSA, signed, private, log)
	case protocol.AUTH_DIGITAL_SIGNATURE:
	default:
		return nil, errors.Errorf("Authentication Method is not supported: %s", authMethod)
	}
	signature, err := signData(algo, signed, private, log)
	if err != nil {
		return nil, err
	}
	// encode rfc7427 signature
	sigAuth := &protocol.SignatureAuth{
		Asn1Data:  certAuthToAsn[algo],
		Signature: signature,
	}
	return sigAuth.Encode(), nil
}

func signData(algo x509.SignatureAlgorithm, signed []byte, priv crypto.Signer, log log.Logger) (signature []byte, err error) {
	log.Log("SignatureAlgorithm", algo)

	var hashType crypto.Hash
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
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
	// TODO - should we check if the key & cert match ??
	return priv.Sign(rand.Reader, digest, hashType)
}
