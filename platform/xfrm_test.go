// +build linux

package platform

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func randomKey() []byte {
	// 256b (32)B key + 4 B salt
	value := make([]byte, 36)
	rand.Read(value)
	return value
}

func TestXfrm(t *testing.T) {
	stateAdd := getState()
	err := netlink.XfrmStateAdd(stateAdd)
	t.Logf("add state %+v: %v", stateAdd, err)

	polAdd := getPolicy()
	err = netlink.XfrmPolicyAdd(polAdd)
	t.Logf("add policy %+v: %v", polAdd, err)

	state, err := netlink.XfrmStateList(0)
	t.Log("state", state, err)
	policy, err := netlink.XfrmPolicyList(0)
	t.Log("policy", policy, err)

	netlink.XfrmPolicyFlush()
	netlink.XfrmStateFlush(0)
}

func getState() *netlink.XfrmState {
	src, _, _ := net.ParseCIDR("192.168.10.1/32")
	dst, _, _ := net.ParseCIDR("192.168.11.1/32")

	return &netlink.XfrmState{
		Src:          src,
		Dst:          dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          3467156381,
		Reqid:        10,
		ReplayWindow: 32,
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    randomKey(),
			ICVLen: 128,
		},
	}
}

func getPolicy() *netlink.XfrmPolicy {
	src, _ := netlink.ParseIPNet("127.1.1.1/32")
	dst, _ := netlink.ParseIPNet("127.1.1.2/32")
	policy := &netlink.XfrmPolicy{
		Src:     src,
		Dst:     dst,
		Proto:   17,
		DstPort: 1234,
		SrcPort: 5678,
		Dir:     netlink.XFRM_DIR_OUT,
		Mark: &netlink.XfrmMark{
			Value: 0xabff22,
			Mask:  0xffffffff,
		},
		Priority: 10,
	}
	tmpl := netlink.XfrmPolicyTmpl{
		Src:   net.ParseIP("127.0.0.1"),
		Dst:   net.ParseIP("127.0.0.2"),
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   0xabcdef99,
	}
	policy.Tmpls = append(policy.Tmpls, tmpl)
	return policy
}
