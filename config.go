package ike

import (
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/pkg/errors"
)

type Config struct {
	ProposalIke, ProposalEsp protocol.Transforms

	LocalID, RemoteID Identity
	AuthMethod        protocol.AuthMethod

	TsI, TsR             []*protocol.Selector
	IsTransportMode      bool
	ThrottleInitRequests bool
}

// StrongSwan recommendations for cipher suite
// aes128-sha256-modp3072 (AES-CBC-128, SHA-256 as HMAC and DH key exchange with 3072 bit key length)
// suite B
// aes128gcm16-prfsha256-ecp256 (AES-GCM-128 AEAD, SHA-256 as PRF and ECDH key exchange with 256 bit key length)
// aes256gcm16-prfsha384-ecp384 (AES-GCM-256 AEAD, SHA-384 as PRF and ECDH key exchange with 384 bit key length)

func DefaultConfig() *Config {
	return &Config{
		// ProposalIke: protocol.IKE_AES_CBC_SHA256_MODP3072,
		// ProposalIke: protocol.IKE_AES_GCM_16_MODP3072,
		ProposalIke: protocol.IKE_AES128GCM16_PRFSHA256_ECP256,
		// ProposalEsp: protocol.ESP_AES_CBC_SHA2_256,
		ProposalEsp: protocol.ESP_AES_GCM_16,
		AuthMethod:  protocol.AUTH_DIGITAL_SIGNATURE,
		// ThrottleInitRequests: true,
	}
}

// CheckProposals checks if incoming proposals include our configuration
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

func SelectorFromAddress(addr *net.IPNet) ([]*protocol.Selector, error) {
	first, last, err := IPNetToFirstLastAddress(addr)
	if err != nil {
		return nil, err
	}
	stype := protocol.TS_IPV4_ADDR_RANGE
	if len(first) == net.IPv6len {
		stype = protocol.TS_IPV6_ADDR_RANGE
	}
	return []*protocol.Selector{&protocol.Selector{
		Type:         stype,
		IpProtocolId: 0,
		StartPort:    0,
		Endport:      65535,
		StartAddress: first,
		EndAddress:   last,
	}}, nil
}

// AddSelector builds selector from address & mask
func (cfg *Config) AddSelector(initiator, responder *net.IPNet) (err error) {
	tsI, err := SelectorFromAddress(initiator)
	if err != nil {
		return
	}
	cfg.TsI = tsI
	tsR, err := SelectorFromAddress(responder)
	if err != nil {
		return
	}
	cfg.TsR = tsR
	return
}

// CheckromAuth checks esp proposal & selector
func (cfg *Config) CheckromAuth(authI *Message) error {
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
	log.V(1).Infof("Configured selectors: [INI]%s<=>%s[RES]", cfg.TsI, cfg.TsR)
	log.V(1).Infof("Offered selectors: [INI]%s<=>%s[RES]", tsI, tsR)
	// TODO - check selectors
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
