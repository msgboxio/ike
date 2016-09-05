// +build linux

package platform

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/msgboxio/context"
	"github.com/vishvananda/netlink"
)

func testXfrmReader(t *testing.T) {
	parent := context.Background()
	cxt := ListenForEvents(parent)
	<-cxt.Done()
}

func randomKey() []byte {
	// 256b (32)B key + 4 B salt
	value := make([]byte, 36)
	rand.Read(value)
	return value
}

func TestXfrmState(t *testing.T) {
	src, _, _ := net.ParseCIDR("192.168.10.1/32")
	dst, _, _ := net.ParseCIDR("192.168.11.1/32")

	stateAdd := netlink.XfrmState{
		Src:          src,
		Dst:          dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          3467156381,
		Reqid:        10,
		ReplayWindow: 32,
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    randomKey(),
			ICVLen: 128,
		},
	}

	err := netlink.XfrmStateAdd(&stateAdd)
	t.Logf("add state %s: %v", stateAdd, err)

	state, err := netlink.XfrmStateList(0)
	t.Log("state", state, err)
	policy, err := netlink.XfrmPolicyList(0)
	t.Log("policy", policy, err)

	netlink.XfrmPolicyFlush()
	netlink.XfrmStateFlush(0)
}
