// +build linux

package platform

import (
	"fmt"
	"net"
	"syscall"

	"msgbox.io/context"
	"msgbox.io/log"
	"msgbox.io/netlink"
)

func makeSaPolicies(reqid int, sa *SaParams) (policies []netlink.XfrmPolicy) {
	// out
	out := netlink.XfrmPolicy{
		Src:      sa.SrcNet,
		Dst:      sa.DstNet,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 1795,
	}
	mode := netlink.XFRM_MODE_TUNNEL
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
	}
	otmpl := netlink.XfrmPolicyTmpl{
		Src:   sa.Src,
		Dst:   sa.Dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Reqid: reqid,
	}
	out.Tmpls = append(out.Tmpls, otmpl)
	policies = append(policies, out)
	// in
	in := netlink.XfrmPolicy{
		Src:      sa.DstNet,
		Dst:      sa.SrcNet,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 1795,
	}
	itmpl := netlink.XfrmPolicyTmpl{
		Src:   sa.Dst,
		Dst:   sa.Src,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Reqid: reqid,
	}
	in.Tmpls = append(in.Tmpls, itmpl)
	policies = append(policies, in)
	// fwd ??
	fwd := netlink.XfrmPolicy{
		Src:      sa.DstNet,
		Dst:      sa.SrcNet,
		Dir:      netlink.XFRM_DIR_FWD,
		Priority: 1795,
	}
	fwd.Tmpls = append(fwd.Tmpls, itmpl)
	policies = append(policies, fwd)
	return policies
}

func makeSelector(src, dst *net.IPNet) (sel *netlink.XfrmSelector) {
	sel = &netlink.XfrmSelector{}
	sel.Family = uint16(netlink.GetIPFamily(dst.IP))
	sel.Daddr.FromIP(dst.IP)
	sel.Saddr.FromIP(src.IP)
	prefixlenD, _ := dst.Mask.Size()
	sel.PrefixlenD = uint8(prefixlenD)
	prefixlenS, _ := src.Mask.Size()
	sel.PrefixlenS = uint8(prefixlenS)
	return
}

func makeSaStates(reqid int, sa *SaParams) (states []netlink.XfrmState) {
	mode := netlink.XFRM_MODE_TUNNEL
	flag := netlink.XFRM_STATE_AF_UNSPEC
	var selIn, selOut *netlink.XfrmSelector
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
		flag = 0
		// selectors
		selOut = makeSelector(sa.SrcNet, sa.DstNet)
		selIn = makeSelector(sa.DstNet, sa.SrcNet)
	}
	out := netlink.XfrmState{
		Sel:          selOut,
		Src:          sa.Src,
		Dst:          sa.Dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
		Spi:          sa.SpiR,
		Reqid:        reqid,
		ReplayWindow: 32,
		Flags:        flag,
		// Auth: &netlink.XfrmStateAlgo{
		// 	Name: "hmac(sha1)",
		// 	Key:  sa.EspAi,
		// },
		// Crypt: &netlink.XfrmStateAlgo{
		// 	Name: "cbc(aes)",
		// 	Key:  sa.EspEi,
		// },
		Aead: &netlink.XfrmStateAlgo{
			Name: "rfc4106(gcm(aes))",
			Key:  sa.EspEi,
		},
	}
	if sa.SrcPort != 0 && sa.DstPort != 0 {
		out.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.SrcPort,
			DstPort: sa.DstPort,
		}
	}
	states = append(states, out)
	in := netlink.XfrmState{
		Sel:          selIn,
		Src:          sa.Dst,
		Dst:          sa.Src,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
		Spi:          sa.SpiI, // not sure why
		Reqid:        reqid,
		ReplayWindow: 32,
		Flags:        flag,
		// Auth: &netlink.XfrmStateAlgo{
		// 	Name: "hmac(sha1)",
		// 	Key:  sa.EspAr,
		// },
		// Crypt: &netlink.XfrmStateAlgo{
		// 	Name: "cbc(aes)",
		// 	Key:  sa.EspEr,
		// },
		Aead: &netlink.XfrmStateAlgo{
			Name: "rfc4106(gcm(aes))",
			Key:  sa.EspEr,
		},
	}
	if sa.SrcPort != 0 && sa.DstPort != 0 {
		in.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.DstPort,
			DstPort: sa.SrcPort,
		}
	}
	states = append(states, in)
	return states
}

func InstallChildSa(sa *SaParams) error {
	ns, err := netlink.GetNetlinkSocket(syscall.NETLINK_XFRM)
	if err != nil {
		return err
	}
	defer ns.Close()

	for _, policy := range makeSaPolicies(256, sa) {
		log.Infof("adding Policy: %+v", policy)
		// create xfrm policy rules
		err = netlink.XfrmPolicyAdd(ns, &policy)
		if err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped adding policy %v because it already exists", policy)
				return err
			} else {
				err = fmt.Errorf("Failed to add policy %v: %v", policy, err)
				return err
			}
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.Infof("adding State: %+v", state)
		// crate xfrm state rules
		err = netlink.XfrmStateAdd(ns, &state)
		if err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped adding state %v because it already exists", state)
				return err
			} else {
				err = fmt.Errorf("Failed to add state %+v: %v", state, err)
				return err
			}
		}
	}
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	ns, err := netlink.GetNetlinkSocket(syscall.NETLINK_XFRM)
	if err != nil {
		return err
	}
	defer ns.Close()
	for _, policy := range makeSaPolicies(256, sa) {
		log.Infof("removing Policy: %+v", policy)
		// create xfrm policy rules
		err = netlink.XfrmPolicyDel(ns, &policy)
		if err != nil {
			err = fmt.Errorf("Failed to remove policy %v: %v", policy, err)
			return err
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.Infof("removing State: %+v", state)
		// crate xfrm state rules
		err = netlink.XfrmStateDel(ns, &state)
		if err != nil {
			err = fmt.Errorf("Failed to remove state %+v: %v", state, err)
			return err
		}
	}
	return nil
}

func Listen(parent context.Context) context.Context {
	cxt, cancel := context.WithCancel(context.Background())
	nsock, err := netlink.Subscribe(syscall.NETLINK_XFRM, []uint32{
	// XFRMNLGRP(ACQUIRE),
	// XFRMNLGRP(EXPIRE),
	// XFRMNLGRP(MIGRATE),
	// XFRMNLGRP(MAPPING),
	})
	if err != nil {
		cancel(err)
		return cxt
	}
	go runReader(cxt, cancel, nsock)
	go waitForCancel(parent, cxt, nsock)
	return cxt
}

func waitForCancel(parent, cxt context.Context, nsock *netlink.NetlinkSocket) {
	select {
	case <-parent.Done():
	case <-cxt.Done():
	}
	nsock.Close()
}

func runReader(cxt context.Context, cancel context.CancelFunc, nsock *netlink.NetlinkSocket) {
	for {
		if msg, err := nsock.Recvmsg(); err != nil {
			log.Error("xfrm Error: %v", err)
			cancel(err)
			return
		} else {
			switch msg.Header.Type {
			case netlink.XFRM_MSG_ACQUIRE:
				log.Infof("acquire: %v", msg.Header)
			case netlink.XFRM_MSG_EXPIRE:
				log.Infof("expire: %v", msg.Header)
			case netlink.XFRM_MSG_MIGRATE:
				log.Infof("migrate: %v", msg.Header)
			case netlink.XFRM_MSG_MAPPING:
				log.Infof("mapping: %v", msg.Header)
			default:
				log.Infof("unknown type: 0x%x\n", msg.Header.Type)
			}
		}
	}

}
