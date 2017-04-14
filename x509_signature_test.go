package ike

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"encoding/hex"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
)

var pemPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`

var testPrivateKey *rsa.PrivateKey
var ecdsaPriv *ecdsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	ecdsaPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate ECDSA key: " + err.Error())
	}
}

func certificate(pvt interface{}, sigAlgo x509.SignatureAlgorithm) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "foo",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Now().AddDate(1, 0, 0),

		BasicConstraintsValid: true,
		IsCA: true,

		KeyUsage:           x509.KeyUsageCertSign,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: sigAlgo,
	}

	var derBytes []byte
	var err error
	if key, ok := pvt.(*rsa.PrivateKey); ok {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	} else {
		eckey := pvt.(*ecdsa.PrivateKey)
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &eckey.PublicKey, eckey)
	}
	if err != nil {
		panic("failed to create certificate:" + err.Error())
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic("Certificate with unknown critical extension was not parsed: " + err.Error())
	}
	return cert
}

func TestSignature(test *testing.T) {
	tests := []struct {
		name       string
		cert       *x509.Certificate
		priv       crypto.Signer
		checkSig   bool
		AuthMethod protocol.AuthMethod
		sigAlgo    x509.SignatureAlgorithm
	}{
		{"RSA/RSA", certificate(testPrivateKey, x509.SHA1WithRSA), testPrivateKey, true, protocol.AUTH_RSA_DIGITAL_SIGNATURE, x509.SHA1WithRSA},
		{"ECDSA/ECDSA", certificate(ecdsaPriv, x509.ECDSAWithSHA1), ecdsaPriv, true, protocol.AUTH_RSA_DIGITAL_SIGNATURE, x509.ECDSAWithSHA1},
		{"ECDSA/ECDSA", certificate(ecdsaPriv, x509.ECDSAWithSHA1), ecdsaPriv, true, protocol.AUTH_DIGITAL_SIGNATURE, x509.ECDSAWithSHA1},
		{"ECDSA/ECDSA", certificate(ecdsaPriv, x509.ECDSAWithSHA384), ecdsaPriv, true, protocol.AUTH_DIGITAL_SIGNATURE, x509.ECDSAWithSHA384},
	}
	log := log.NewLogfmtLogger(os.Stdout)
	data := []byte("qwertyy12345")
	for _, t := range tests {
		sig, err := CreateSignature(t.sigAlgo, t.AuthMethod, data, t.priv, log)
		if err != nil {
			test.Error(err)
		}
		test.Logf("\n%s", hex.Dump(sig))
		err = VerifySignature(t.AuthMethod, data, sig, t.cert, log)
		if t.checkSig {
			if err != nil {
				test.Error(err)
			}
		} else {
			if err == nil {
				test.Error("signature should have failed")
			}
		}
	}
}
