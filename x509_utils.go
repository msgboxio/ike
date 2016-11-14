package ike

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"time"

	"encoding/pem"

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

func LoadPEMCert(certFile string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	return x509.ParseCertificate(block.Bytes)
}

func LoadCerts(certFile string) ([]*x509.Certificate, error) {
	certDER, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificates(certDER)
}

func LoadKey(keyFile string) (*rsa.PrivateKey, error) {
	keyDER, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(keyDER)
}

// AltNames contains the domain names and IP addresses that will be added
// to the API Server's x509 certificate SubAltNames field. The values will
// be passed directly to the x509.Certificate object.
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
	Emails   []string
}

type CertID struct {
	CommonName          string
	Organization        []string
	AltNames            AltNames
	Issuer              string
	NotBefore, NotAfter time.Time
	IsCA                bool
}

func (c *CertID) alts() (names []string) {
	for _, d := range c.AltNames.DNSNames {
		names = append(names, d)
	}
	for _, d := range c.AltNames.IPs {
		names = append(names, d.String())
	}
	for _, d := range c.AltNames.Emails {
		names = append(names, d)
	}
	return
}

func (c *CertID) String() string {
	res := fmt.Sprintf(
		"Issuer: CN=%s | Subject: CN=%s | CA: %t ",
		c.Issuer, c.CommonName, c.IsCA,
	)
	res += fmt.Sprintf("| Not before: %s Not After: %s", c.NotBefore, c.NotAfter)
	if an := c.alts(); len(an) > 0 {
		res += fmt.Sprintf(" | Alternate Names: %v", an)
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
	id.AltNames.IPs = append([]net.IP{}, c.IPAddresses...)
	id.AltNames.DNSNames = append([]string{}, c.DNSNames...)
	id.AltNames.Emails = append([]string{}, getEmail(c)...)
	id.Issuer = c.Issuer.CommonName
	id.CommonName = c.Subject.CommonName
	id.Organization = c.Subject.Organization
	id.IsCA = c.IsCA
	id.NotBefore = c.NotBefore
	id.NotAfter = c.NotAfter
	return
}

// MatchNameFromCert checks if name is specified in Subject or Altnames
func MatchNameFromCert(cert *CertID, name string) bool {
	if cert.CommonName != "" && cert.CommonName == name {
		return true
	}
	for _, alt := range cert.alts() {
		if alt != "" && alt == name {
			return true
		}
	}
	return false
}

// NewSelfSignedCACert creates a CA certificate
func NewECCA(name string) (*x509.Certificate, interface{}, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create a private key for a new CA: %v", err)
	}

	cfg := CertID{
		CommonName: name,
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(time.Hour).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDERBytes)
	return cert, key, err
}

// NewSignedCert creates a signed certificate using the given CA certificate and key
func NewSignedCert(cfg CertID, publicKey interface{}, caCert *x509.Certificate, caKey interface{}) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	certTmpl := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: caCert.Subject.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(time.Hour).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, caCert, publicKey, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}
