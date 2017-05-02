// +build linux

package platform

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/vishvananda/netlink"
)

func TestInitSpi(t *testing.T) {
	src, snet, _ := net.ParseCIDR("172.28.128.3/32")
	dst, dnet, _ := net.ParseCIDR("172.28.128.4/32")
	_ = snet
	_ = dnet

	sa, err := netlink.XfrmStateAllocSpi(&netlink.XfrmState{
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
	})
	if err != nil {
		t.Error(err)
	}
	t.Logf("sa: %s", spew.Sdump(sa))

	sa.Src = src
	sa.Aead = &netlink.XfrmStateAlgo{
		Name:   "rfc4106(gcm(aes))",
		Key:    key(36),
		ICVLen: 128,
	}
	sa.Mode = netlink.XFRM_MODE_TUNNEL
	if err := netlink.XfrmStateUpdate(sa); err != nil {
		t.Error(err)
	}
	// needed for delete state
	err = netlink.XfrmStateDel(&netlink.XfrmState{
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   sa.Spi,
	})
	if err != nil {
		t.Error(err)
	}
}

// policy
// will block both sided traffic
func TestXfrmPolicy(t *testing.T) {
	doPol := func(src, dst string) {
		err := netlink.XfrmPolicyAdd(getPolicy(src, dst, netlink.XFRM_DIR_OUT))
		if err != nil {
			t.Error(err)
		}

		err = netlink.XfrmPolicyAdd(getPolicy(dst, src, netlink.XFRM_DIR_IN))
		if err != nil {
			t.Error(err)
		}

		policy, err := netlink.XfrmPolicyList(0)
		if err != nil {
			t.Error(err)
		}
		t.Log("list policy", policy, err)
	}
	doPol("172.28.128.3/24", "172.28.128.4/24")
	// netlink.XfrmPolicyFlush()
}

func getPolicy(src, dst string, dir netlink.Dir) *netlink.XfrmPolicy {
	s, snet, _ := net.ParseCIDR(src)
	d, dnet, _ := net.ParseCIDR(dst)
	policy := &netlink.XfrmPolicy{
		Src: snet,
		Dst: dnet,
		Dir: dir,
	}
	tmpl := netlink.XfrmPolicyTmpl{
		Src:   s,
		Dst:   d,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
	}
	policy.Tmpls = append(policy.Tmpls, tmpl)
	return policy
}

// statte

func TestXfrmState(t *testing.T) {
	stateAdd := getState()
	err := netlink.XfrmStateAdd(stateAdd)
	t.Logf("add state %+v: %v", stateAdd, err)

	state, err := netlink.XfrmStateList(0)
	t.Log("state", state, err)

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
			Key:    key(36),
			ICVLen: 128,
		},
	}
}

func TestMonitor(t *testing.T) {
	logger := log.NewLogfmtLogger(os.Stdout)
	cb := func(msg interface{}) {
		switch m := msg.(type) {
		case *netlink.XfrmMsgExpire:
			logger.Log("expire", spew.Sdump(m))
		case *netlink.XfrmMsgAcquire:
			logger.Log("acquire", spew.Sdump(m))
		}
	}
	cxt := context.Background()
	ListenForEvents(cxt, cb, logger)
	<-cxt.Done()
}
