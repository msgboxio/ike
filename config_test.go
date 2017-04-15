package ike

import (
	"net"
	"reflect"
	"testing"

	"github.com/msgboxio/ike/protocol"
)

func TestCopyConfig(t *testing.T) {
	def := DefaultConfig()
	copy := *def
	_, ipnet, _ := net.ParseCIDR("10.0.0.10/24")
	copy.AddSelector(ipnet, ipnet)
	if reflect.DeepEqual(def.TsI, copy.TsI) {
		t.FailNow()
	}
}

func TestCheckProposals(t *testing.T) {
	cfg := &Config{
		ProposalIke: protocol.IKE_AES128GCM16_PRFSHA256_ECP256,
		ProposalEsp: protocol.ESP_AES_CBC_SHA2_256,
	}
	ikeProps := []*protocol.SaProposal{
		&protocol.SaProposal{
			ProtocolId: protocol.IKE,
			SaTransforms: []*protocol.SaTransform{
				&protocol.SaTransform{Transform: protocol.T_AEAD_AES_GCM_16, KeyLength: 128},
				&protocol.SaTransform{Transform: protocol.T_PRF_HMAC_SHA2_256},
				&protocol.SaTransform{Transform: protocol.T_ECP_256, IsLast: true},
			},
		},
	}
	if err := cfg.CheckProposals(protocol.IKE, ikeProps); err != nil {
		t.Error(err)
	}
	ipsecProps := []*protocol.SaProposal{
		&protocol.SaProposal{
			ProtocolId: protocol.ESP,
			SaTransforms: []*protocol.SaTransform{
				&protocol.SaTransform{Transform: protocol.T_ENCR_AES_CBC, KeyLength: 128},
				&protocol.SaTransform{Transform: protocol.T_AUTH_HMAC_SHA2_256_128},
				&protocol.SaTransform{Transform: protocol.T_NO_ESN, IsLast: true},
			},
		},
	}
	if err := cfg.CheckProposals(protocol.ESP, ipsecProps); err != nil {
		t.Error(err)
	}
	if err := cfg.CheckProposals(protocol.IKE, ipsecProps); err == nil {
		t.Fail()
	}
}
