// +build linux

package platform

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"syscall"
	"testing"

	"github.com/msgboxio/context"
	"github.com/msgboxio/netlink"
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

func TestAddState(t *testing.T) {
	ns, err := netlink.GetNetlinkSocket(syscall.NETLINK_XFRM)
	if err != nil {
		t.Error(err)
	}
	defer ns.Close()
	src, srcNet, _ := net.ParseCIDR("192.168.10.1/32")
	dst, dstNet, _ := net.ParseCIDR("192.168.11.1/32")

	state := netlink.XfrmState{
		Sel:          makeSelector(srcNet, dstNet),
		Src:          src,
		Dst:          dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          3467156381,
		Reqid:        0,
		ReplayWindow: 32,
		Flags:        0,
		Aead: &netlink.XfrmStateAlgo{
			Name: "rfc4106(gcm(aes))",
			Key:  randomKey(),
		},
	}

	statejs, _ := json.Marshal(state)
	t.Logf("add state %s: %v", string(statejs), err)

	err = netlink.XfrmStateAdd(ns, &state)
	if err != nil {
		t.Error(err)
	}
}
