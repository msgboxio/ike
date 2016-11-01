package ike

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"time"

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

type CertID struct {
	Altnames            []string
	Issuer              string
	Subject             string
	NotBefore, NotAfter time.Time
	IsCA                bool
}

func (c *CertID) String() string {
	res := fmt.Sprintf(
		"Issuer: CN=%s | Subject: CN=%s | CA: %t ",
		c.Issuer, c.Subject, c.IsCA,
	)
	res += fmt.Sprintf("| Not before: %s Not After: %s", c.NotBefore, c.NotAfter)
	if len(c.Altnames) > 0 {
		res += fmt.Sprintf(" | Alternate Names: %v", c.Altnames)
	}
	return res
}

func getEmail(c *x509.Certificate) []string {
	if len(c.EmailAddresses) != 0 {
		return []string{c.EmailAddresses[0]}
	}
	var emailAddressOID asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 9, 1}
	for _, name := range c.Subject.Names {
		if name.Type.Equal(emailAddressOID) {
			return []string{name.Value.(string)}
		}
	}
	return []string{}
}

// FormatCert receives certificate and formats in human-readable format
func FormatCert(c *x509.Certificate) (id CertID) {
	var name []string
	for _, ip := range c.IPAddresses {
		name = append(name, ip.String())
	}
	id.Altnames = append(name, c.DNSNames...)
	id.Altnames = append(name, getEmail(c)...)
	id.Issuer = c.Issuer.CommonName
	id.Subject = c.Subject.CommonName
	id.IsCA = c.IsCA
	id.NotBefore = c.NotBefore
	id.NotAfter = c.NotAfter
	return
}

// MatchNameFromCert checks if name is specified in Subject or Altnames
func MatchNameFromCert(cert *CertID, name string) bool {
	if cert.Subject != "" && cert.Subject == name {
		return true
	}
	for _, alt := range cert.Altnames {
		if alt != "" && alt == name {
			return true
		}
	}
	return false
}
