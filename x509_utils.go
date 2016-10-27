package ike

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
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

// FormatCert receives certificate and formats in human-readable format
func FormatCert(c *x509.Certificate) string {
	var ips []string
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	altNames := append(ips, c.DNSNames...)
	res := fmt.Sprintf(
		"Issuer: CN=%s | Subject: CN=%s | CA: %t ",
		c.Issuer.CommonName, c.Subject.CommonName, c.IsCA,
	)
	res += fmt.Sprintf("| Not before: %s Not After: %s", c.NotBefore, c.NotAfter)
	if len(altNames) > 0 {
		res += fmt.Sprintf(" | Alternate Names: %v", altNames)
	}
	return res
}
