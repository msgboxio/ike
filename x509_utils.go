package ike

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"

	"github.com/pkg/errors"
)

func LoadRoot(caCert string) (*x509.CertPool, error) {
	// try and load the system certs if caCert has not been given
	if caCert == "" {
		return x509.SystemCertPool()
	}
	roots := x509.NewCertPool()
	rootPEM, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	if ok := roots.AppendCertsFromPEM([]byte(rootPEM)); !ok {
		return nil, errors.New("failed to parse root certificate")
	}
	return roots, nil
}

func LoadCerts(certFile string) ([]*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificates(certPEM)
}

func LoadKey(keyFile string) (*rsa.PrivateKey, error) {
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(keyPEM)
}
