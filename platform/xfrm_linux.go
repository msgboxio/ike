package platform

import (
	"fmt"
	"net"
	"syscall"

	"msgbox.io/log"
	"msgbox.io/netlink"
)

func getPolicies(reqid int, src net.IP, dst net.IP, srcNet *net.IPNet, dstNet *net.IPNet) (policies []netlink.XfrmPolicy) {
	out := netlink.XfrmPolicy{
		Src:      srcNet,
		Dst:      dstNet,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 1795,
	}
	otmpl := netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Reqid: reqid,
	}
	out.Tmpls = append(out.Tmpls, otmpl)
	policies = append(policies, out)

	in := netlink.XfrmPolicy{
		Src:      dstNet,
		Dst:      srcNet,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 1795,
	}
	itmpl := netlink.XfrmPolicyTmpl{
		Src:   dst,
		Dst:   src,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Reqid: reqid,
	}
	in.Tmpls = append(in.Tmpls, itmpl)
	policies = append(policies, in)

	fwd := netlink.XfrmPolicy{
		Src:      dstNet,
		Dst:      srcNet,
		Dir:      netlink.XFRM_DIR_FWD,
		Priority: 1795,
	}
	fwd.Tmpls = append(fwd.Tmpls, itmpl)
	policies = append(policies, fwd)
	return policies
}

func getStates(reqid int, sa *SaParams) []netlink.XfrmState {
	states := make([]netlink.XfrmState, 0)
	out := netlink.XfrmState{
		Src:          sa.Src,
		Dst:          sa.Dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          sa.SpiR,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha1)",
			Key:  sa.EspAi,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  sa.EspEi,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name: "rfc4106(gcm(aes))",
		// 	Key:  encKey,
		// },
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
		Src:          sa.Dst,
		Dst:          sa.Src,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TUNNEL,
		Spi:          sa.SpiI, // not sure why
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha1)",
			Key:  sa.EspAr,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  sa.EspEr,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name: "rfc4106(gcm(aes))",
		// 	Key:  encKey,
		// },
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

	for _, policy := range getPolicies(256, sa.Src, sa.Dst, sa.SrcNet, sa.DstNet) {
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
	for _, state := range getStates(256, sa) {
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
	for _, policy := range getPolicies(256, sa.Src, sa.Dst, sa.SrcNet, sa.DstNet) {
		log.Infof("removing Policy: %+v", policy)
		// create xfrm policy rules
		err = netlink.XfrmPolicyDel(ns, &policy)
		if err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped remove policy %v because it already exists", policy)
				return err
			} else {
				err = fmt.Errorf("Failed to remove policy %v: %v", policy, err)
				return err
			}
		}
	}
	for _, state := range getStates(256, sa) {
		log.Infof("removing State: %+v", state)
		// crate xfrm state rules
		err = netlink.XfrmStateDel(ns, &state)
		if err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped removing state %v because it already exists", state)
				return err
			} else {
				err = fmt.Errorf("Failed to remove state %+v: %v", state, err)
				return err
			}
		}
	}
	return nil
}
