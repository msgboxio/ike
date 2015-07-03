package platform

import (
	"fmt"
	"net"
	"syscall"

	"msgbox.io/log"
	"msgbox.io/netlink"
)

func getPolicies(reqid int, src net.IP, dst net.IP, srcNet *net.IPNet, dstNet *net.IPNet) []netlink.XfrmPolicy {
	policies := make([]netlink.XfrmPolicy, 0)
	out := netlink.XfrmPolicy{
		Src: srcNet,
		Dst: dstNet,
		Dir: netlink.XFRM_DIR_OUT,
	}
	otmpl := netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Reqid: reqid,
	}
	out.Tmpls = append(out.Tmpls, otmpl)
	policies = append(policies, out)
	in := netlink.XfrmPolicy{
		Src: dstNet,
		Dst: srcNet,
		Dir: netlink.XFRM_DIR_IN,
	}
	itmpl := netlink.XfrmPolicyTmpl{
		Src:   dst,
		Dst:   src,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Reqid: reqid,
	}
	in.Tmpls = append(in.Tmpls, itmpl)
	policies = append(policies, in)
	return policies
}

func getStates(reqid int, src, dst net.IP, srcPort, dstPort int, espEi, espAi, espEr, espAr []byte) []netlink.XfrmState {
	states := make([]netlink.XfrmState, 0)
	out := netlink.XfrmState{
		Src:          src,
		Dst:          dst,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          reqid,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha1)",
			Key:  espAi,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  espEi,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name: "rfc4106(gcm(aes))",
		// 	Key:  encKey,
		// },
	}
	if srcPort != 0 && dstPort != 0 {
		out.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: srcPort,
			DstPort: dstPort,
		}
	}
	states = append(states, out)
	in := netlink.XfrmState{
		Src:          dst,
		Dst:          src,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          reqid,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha1)",
			Key:  espAr,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  espEr,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name: "rfc4106(gcm(aes))",
		// 	Key:  encKey,
		// },
	}
	if srcPort != 0 && dstPort != 0 {
		in.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: dstPort,
			DstPort: srcPort,
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

	for _, policy := range getPolicies(0x01, sa.Src, sa.Dst, sa.SrcNet, sa.DstNet) {
		log.Infof("building Policy: %v", policy)
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
	for _, state := range getStates(256, sa.Src, sa.Dst, sa.SrcPort, sa.DstPort, sa.EspEi, sa.EspAi, sa.EspEr, sa.EspAr) {
		log.Infof("building State: %+v", state)
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
