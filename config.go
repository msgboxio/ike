package ike

import (
	"net"
	"reflect"
	"time"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

type Config struct {
	ProposalIke, ProposalEsp protocol.Transforms

	LocalID, RemoteID Identity
	AuthMethod        protocol.AuthMethod

	TsI, TsR             protocol.Selectors
	IsTransportMode      bool
	ThrottleInitRequests bool
	Lifetime             time.Duration
}

// StrongSwan recommendations for cipher suite
// aes128-sha256-modp3072 (AES-CBC-128, SHA-256 as HMAC and DH key exchange with 3072 bit key length)
// suite B
// aes128gcm16-prfsha256-ecp256 (AES-GCM-128 AEAD, SHA-256 as PRF and ECDH key exchange with 256 bit key length)
// aes256gcm16-prfsha384-ecp384 (AES-GCM-256 AEAD, SHA-384 as PRF and ECDH key exchange with 384 bit key length)

func DefaultConfig() *Config {
	return &Config{
		AuthMethod: protocol.AUTH_DIGITAL_SIGNATURE,
		// ThrottleInitRequests: true,
		Lifetime: time.Hour,
	}
}

//
// proposals
//

// CheckProposals checks if incoming proposals include our configuration
func (cfg *Config) CheckProposals(prot protocol.ProtocolID, proposals protocol.Proposals) (err error) {
	for _, prop := range proposals {
		if prop.ProtocolID != prot {
			continue
		}
		// select first acceptable one from the list
		switch prot {
		case protocol.IKE:
			if err = cfg.ProposalIke.Within(prop.SaTransforms); err != nil {
				break
			}
		case protocol.ESP:
			if err = cfg.ProposalEsp.Within(prop.SaTransforms); err != nil {
				break
			}
		}
	}
	if err == nil {
		return
	}
	return errors.Wrap(protocol.ERR_NO_PROPOSAL_CHOSEN, err.Error())
}

func ProposalFromTransform(prot protocol.ProtocolID, trs protocol.Transforms, spi []byte) []*protocol.SaProposal {
	return []*protocol.SaProposal{
		&protocol.SaProposal{
			IsLast:       true,
			Number:       1,
			ProtocolID:   prot,
			Spi:          append([]byte{}, spi...),
			SaTransforms: trs.AsList(),
		},
	}
}

func (cfg *Config) CheckDhTransform(dhID protocol.DhTransformId) error {
	// make sure dh tranform id is the one that was configured
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != dhID {
		return errors.Wrapf(protocol.ERR_INVALID_KE_PAYLOAD,
			"IKE_SA_INIT: Using different DH transform [%s] vs the one configured [%s]",
			dhID, dh) // C.1
	}
	return nil
}

//
// selectors
//

// CheckSelectors checks if incoming selectors match our configuration
func (cfg *Config) CheckSelectors(tsi, tsr []*protocol.Selector, isTransportMode bool) error {
	p1 := cfg.Policy()
	p2 := selectorsToPolicy(tsi[0], tsr[0], isTransportMode)
	if !reflect.DeepEqual(p1, p2) {
		return errors.WithStack(protocol.ERR_INVALID_SELECTORS)
	}
	// // transport mode
	// if isTransportMode && cfg.IsTransportMode {
	// } else {
	// 	// one side wants tunnel mode
	// 	if isTransportMode {
	// 		// sess.Logger.Log("Mode", "Peer Requested TRANSPORT, configured TUNNEL")
	// 		return errors.Wrap(protocol.ERR_INVALID_SELECTORS, "Reject TRANSPORT Mode Request")
	// 	} else if cfg.IsTransportMode {
	// 		// sess.Logger.Log("Mode", "Peer Requested TUNNEL, configured TRANSPORT")
	// 		return errors.Wrap(protocol.ERR_INVALID_SELECTORS, "Reject TUNNEL Mode Request")
	// 	} else {
	// 		// sess.Logger.Log("Mode", "TUNNEL")
	// 	}
	// }
	return nil
}

func selectorFromAddress(addr *net.IPNet) ([]*protocol.Selector, error) {
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

// AddNetworkSelectors builds selector from address & mask
func (cfg *Config) AddNetworkSelectors(localnet, remotenet *net.IPNet, forInitiator bool) (err error) {
	local, err := selectorFromAddress(localnet)
	if err != nil {
		return
	}
	remote, err := selectorFromAddress(remotenet)
	if err != nil {
		return
	}
	// MUTATION
	cfg.TsI = remote
	cfg.TsR = local
	if forInitiator {
		cfg.TsI = local
		cfg.TsR = remote
	}
	return
}

// AddHostSelectors builds selectors from ip addresses
func (cfg *Config) AddHostSelectors(local, remote net.IP, forInitiator bool) error {
	slen := len(local) * 8
	// MUTATION
	err := cfg.AddNetworkSelectors(
		&net.IPNet{IP: local, Mask: net.CIDRMask(slen, slen)},
		&net.IPNet{IP: remote, Mask: net.CIDRMask(slen, slen)},
		forInitiator)
	if err != nil {
		return errors.Wrapf(err, "could not add selectors for %s=>%s", local, remote)
	}
	return nil
}

// Policy converts the selectors to policy
func (cfg *Config) Policy() *protocol.PolicyParams {
	return selectorsToPolicy(cfg.TsI[0], cfg.TsR[0], cfg.IsTransportMode)
}

func selectorsToPolicy(tsI, tsR *protocol.Selector, isTransportMode bool) *protocol.PolicyParams {
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	return &protocol.PolicyParams{
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		IsTransportMode: isTransportMode,
	}
}
