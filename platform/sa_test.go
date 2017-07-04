package platform

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func makeSpi() int {
	spi, _ := rand.Prime(rand.Reader, 32)
	return int(spi.Int64())
}

func key(len int) []byte {
	value := make([]byte, len)
	rand.Read(value)
	return value
}

// adding this policy should drop outgoing packets from src to dst
func TestAddPolicy(t *testing.T) {
	src, snet, _ := net.ParseCIDR("172.28.128.3/32")
	dst, dnet, _ := net.ParseCIDR("172.28.128.4/32")
	sa := &SaParams{
		PolicyParams: &protocol.PolicyParams{
			IniNet:          snet,
			Ini:             src.To4(),
			ResNet:          dnet,
			Res:             dst.To4(),
			IsTransportMode: true,
		},
	}
	err := InstallPolicy(0, sa.PolicyParams, log.NewNopLogger(), true)
	if err != nil {
		t.Error(err)
	}
	// netlink.XfrmPolicyFlush()
}

func TestAddSa(t *testing.T) {
	local, localNet, _ := net.ParseCIDR("192.168.20.1/24")
	remote, remoteNet, _ := net.ParseCIDR("192.168.40.1/24")

	// 128b (16B) key + 4B salt
	// 256b (32)B key + 4 B salt
	sa := &SaParams{
		PolicyParams: &protocol.PolicyParams{
			// src, dst for initiator
			Ini:             local.To4(),
			Res:             remote.To4(),
			IniPort:         0,
			ResPort:         0,
			IniNet:          localNet,
			ResNet:          remoteNet,
			IsTransportMode: true,
		},
		EspTransforms: crypto.Aes128Sha256, // aes-cbc + hmac-sha2
		EspEi:         key(16),
		EspAi:         key(32),
		EspEr:         key(16),
		EspAr:         key(32),
		SpiI:          makeSpi(),
		SpiR:          makeSpi(),
	}
	if err := InstallChildSa(0, sa, log.NewNopLogger()); err != nil {
		t.Error(err)
	}
	// state, err := netlink.XfrmStateList(0)
	// t.Log("state", state, err)
	// policy, err := netlink.XfrmPolicyList(0)
	// t.Log("policy", policy, err)
	// netlink.XfrmPolicyFlush()
	// netlink.XfrmStateFlush(0)
}
