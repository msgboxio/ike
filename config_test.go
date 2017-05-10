package ike

import (
	"net"
	"reflect"
	"testing"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func TestCopyConfig(t *testing.T) {
	def := DefaultConfig()
	copy := *def
	_, ipnet, _ := net.ParseCIDR("10.0.0.10/24")
	copy.AddNetworkSelectors(ipnet, ipnet, true)
	if reflect.DeepEqual(def.TsI, copy.TsI) {
		t.FailNow()
	}
}

func TestCheckProposals(t *testing.T) {
	cfg := &Config{
		ProposalIke: crypto.Aes128gcm16Prfsha256Ecp256,
		ProposalEsp: crypto.Aes256gcm16,
	}
	ikeProps := crypto.Aes128gcm16Prfsha256Ecp256.AsProposal(protocol.IKE)
	if err := cfg.CheckProposals(protocol.IKE, ikeProps); err != nil {
		t.Error(err)
	}
	ipsecProps := crypto.Aes256gcm16.AsProposal(protocol.ESP)
	if err := cfg.CheckProposals(protocol.ESP, ipsecProps); err != nil {
		t.Error(err)
	}
	if err := cfg.CheckProposals(protocol.IKE, ipsecProps); err == nil {
		t.Fail()
	}
}
