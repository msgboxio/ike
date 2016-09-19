package ike

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
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
