package ike

import (
	"crypto/x509"
	"errors"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type Config struct {
	ProposalIke, ProposalEsp protocol.Transforms

	TsI, TsR []*protocol.Selector

	IsTransportMode bool
	Roots           *x509.CertPool
}

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAOtVymGwN2rvMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwOTEyMDMwMDQyWhcNMTcwOTEyMDMwMDQyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA3VFk1V/8qI8bW/3RGiYNJVEJxllbRRsGqgpVyGLj5xakRONB/Cmu+LEV
DoHNQPtVPW2Y/cUcr5kuCHscWqYMC6zs1PcZdY08uli/pMv6+KFE8e1kugc8MwsO
mWgn8GdPGdc9biV89EXL0OsNCphynnYhSw9Ww7LSJAybODql21vs8kJ0X7y0xfEl
t7QQWHKiNv8BcsrsrTpQif3gzm0SnZ1avqunRRcGHw0DkDKsocQlLBJbyIBuoRb1
hVjXH9obaxJXqj6O2wJB3Lzi9rt+q2rANMYWo00qjcwxjxvGqAvxAXJjYFF9+LYL
F4+oad42HCgauoMMgHX/jO3xLeQG2QIDAQABo1AwTjAdBgNVHQ4EFgQUeYe479Gr
jUFgoBQ4GebBQLFaKAMwHwYDVR0jBBgwFoAUeYe479GrjUFgoBQ4GebBQLFaKAMw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWpWtbyypse6OYLhw3JEq
Xe0ZNXnHGmgp2pxVU/FSntizcNucS94e58QGmw13rgc/sqixOqkRSKcpmDC0ljoF
mspogQQ80PYHg6ETzA5M5//5jSRnOJHMupxRbYAna7EbWrhJqnBc3iRVVBIVUJCk
UOxThKwT2RPlWOKQ+nmre6cUoUHthhGmeN/4pMG7hEw67BPAdr/UhWzmXh9WkEoE
OQ7eSTDE8H/FdSznADmWIzRV/YYLoeoz6pODZzp5cbupnTSZwVmw2Z4AJWR9Li8j
vZvgNl+ijE1YGggNGoQnFpiE7jNftxdDif/WFKXT+9ubMCyWKKaQ5GdfsWwjaH5W
jA==
-----END CERTIFICATE-----`

func DefaultConfig() *Config {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	return &Config{
		//Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		ProposalIke: protocol.IKE_AES_GCM_16_DH_2048,
		//Transforms: protocol.ESP_AES_CBC_SHA1_96,
		ProposalEsp: protocol.ESP_AES_GCM_16,
		Roots:       roots,
	}
}

func (cfg *Config) CheckProposals(prot protocol.ProtocolId, proposals protocol.Proposals) error {
	for _, prop := range proposals {
		if prop.ProtocolId != prot {
			continue
		}
		// select first acceptable one from the list
		switch prot {
		case protocol.IKE:
			if cfg.ProposalIke.Within(prop.SaTransforms) {
				return nil
			}
		case protocol.ESP:
			if cfg.ProposalEsp.Within(prop.SaTransforms) {
				return nil
			}
		}
	}
	return errors.New("acceptable proposals are missing")
}

// AddSelector builds selector from address & mask
func (cfg *Config) AddSelector(initiator, responder *net.IPNet) (err error) {
	first, last, err := IPNetToFirstLastAddress(initiator)
	if err != nil {
		return
	}
	cfg.TsI = []*protocol.Selector{&protocol.Selector{
		Type:         protocol.TS_IPV4_ADDR_RANGE,
		IpProtocolId: 0,
		StartPort:    0,
		Endport:      65535,
		StartAddress: first,
		EndAddress:   last,
	}}
	first, last, err = IPNetToFirstLastAddress(responder)
	if err != nil {
		return
	}
	cfg.TsR = []*protocol.Selector{&protocol.Selector{
		Type:         protocol.TS_IPV4_ADDR_RANGE,
		IpProtocolId: 0,
		StartPort:    0,
		Endport:      65535,
		StartAddress: first,
		EndAddress:   last,
	}}
	return
}

// NewConfigFromInit takes an IkeSaInit message and returns a Config
// if acceptable IKE proposal is available
// Note: Currently This only checks if default Config's IKE config is available
func NewConfigFromInit(initI *Message) (*Config, error) {
	cfg := DefaultConfig()
	// get SA payload
	ikeSa := initI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	if err := cfg.CheckProposals(protocol.IKE, ikeSa.Proposals); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Adds esp proposal & selector
func (cfg *Config) AddFromAuth(authI *Message) error {
	espSa := authI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	if err := cfg.CheckProposals(protocol.ESP, espSa.Proposals); err != nil {
		return err
	}
	// get selectors
	tsI := authI.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
	tsR := authI.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
	if len(tsI) == 0 || len(tsR) == 0 {
		return errors.New("acceptable traffic selectors are missing")
	}
	log.Infof("Configured selectors: [INI]%s<=>%s[RES]", cfg.TsI, cfg.TsR)
	log.Infof("Offered selectors: [INI]%s<=>%s[RES]", tsI, tsR)
	// TODO - dont blindly overwrite
	// cfg.TsI = tsI
	// cfg.TsR = tsR
	return nil
}

func ProposalFromTransform(prot protocol.ProtocolId, trs protocol.Transforms, spi []byte) []*protocol.SaProposal {
	return []*protocol.SaProposal{
		&protocol.SaProposal{
			IsLast:       true,
			Number:       1,
			ProtocolId:   prot,
			Spi:          append([]byte{}, spi...),
			SaTransforms: trs.AsList(),
		},
	}
}
