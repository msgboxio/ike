// +build linux

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"

	"github.com/msgboxio/log"
	"github.com/vishvananda/netlink"
)

// src & dst are tunnel endpoints; ignored for transport mode
func makeTemplate(src, dst net.IP, reqId uint32, isTransportMode bool) netlink.XfrmPolicyTmpl {
	mode := netlink.XFRM_MODE_TUNNEL
	if isTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
		src = net.IPv4zero.To4()
		dst = net.IPv4zero.To4()
	}
	return netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Reqid: int(reqId),
	}
}

func makeSaPolicies(reqId uint32, sa *SaParams) (policies []*netlink.XfrmPolicy) {
	// ini
	ini := &netlink.XfrmPolicy{
		Src:     sa.IniNet,
		Dst:     sa.ResNet,
		Proto:   0,
		SrcPort: sa.IniPort,
		DstPort: sa.ResPort,
		Dir:     netlink.XFRM_DIR_OUT,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: 10,
	}
	ini.Tmpls = append(ini.Tmpls, makeTemplate(sa.Ini, sa.Res, reqId, sa.IsTransportMode))
	if sa.IsResponder {
		ini.Dir = netlink.XFRM_DIR_IN
	}
	policies = append(policies, ini)

	// responder
	resp := &netlink.XfrmPolicy{
		Src:     sa.ResNet,
		Dst:     sa.IniNet,
		Proto:   0,
		SrcPort: sa.ResPort,
		DstPort: sa.IniPort,
		Dir:     netlink.XFRM_DIR_IN,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: 10,
	}
	if sa.IsResponder {
		resp.Dir = netlink.XFRM_DIR_OUT
	}
	resp.Tmpls = append(resp.Tmpls, makeTemplate(sa.Res, sa.Ini, reqId, sa.IsTransportMode))
	policies = append(policies, resp)
	if !sa.IsTransportMode {
		// fwd ??
		// TODO - lost forwarding functionality for now
		// fwd := &netlink.XfrmPolicy{
		// Dir:      netlink.XFRM_DIR_FWD,
		// Priority: 1795,
		// }
		// policies = append(policies, fwd)
	}
	return policies
}

func makeSaStates(reqid int, sa *SaParams) (states []*netlink.XfrmState) {
	mode := netlink.XFRM_MODE_TUNNEL
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
	}
	out := &netlink.XfrmState{
		Src:          sa.Ini,
		Dst:          sa.Res,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
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
		// 	Name:   "rfc4106(gcm(aes))",
		// 	Key:    sa.EspEi,
		// 	ICVLen: 128,
		// },
	}
	if sa.IniPort != 0 && sa.ResPort != 0 {
		out.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.IniPort,
			DstPort: sa.ResPort,
		}
	}
	states = append(states, out)
	in := &netlink.XfrmState{
		Src:          sa.Res,
		Dst:          sa.Ini,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
		Spi:          sa.SpiI,
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
		// 	Name:   "rfc4106(gcm(aes))",
		// 	Key:    sa.EspEr,
		// 	ICVLen: 128,
		// },
	}
	if sa.IniPort != 0 && sa.ResPort != 0 {
		in.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.ResPort,
			DstPort: sa.IniPort,
		}
	}
	states = append(states, in)
	return states
}

func InstallChildSa(sa *SaParams) error {
	for _, policy := range makeSaPolicies(256, sa) {
		log.V(3).Infof("adding Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped adding policy %v because it already exists", policy)
			} else {
				err = fmt.Errorf("Failed to add policy %v: %v", policy, err)
			}
			log.Errorf("Error adding policy: %s", err)
			return err
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.V(3).Infof("adding State: %+v", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateAdd(state); err != nil {
			if err == syscall.EEXIST {
				err = fmt.Errorf("Skipped adding state %v because it already exists", state)
			} else {
				statejs, _ := json.Marshal(state)
				err = fmt.Errorf("Failed to add state %s: %v", string(statejs), err)
			}
			log.Errorf("%s", err)
			return err
		}
	}
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	for _, policy := range makeSaPolicies(256, sa) {
		log.V(3).Infof("removing Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyDel(policy); err != nil {
			err = fmt.Errorf("Failed to remove policy %v: %v", policy, err)
			return err
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.V(3).Infof("removing State: %+v", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateDel(state); err != nil {
			err = fmt.Errorf("Failed to remove state %+v: %v", state, err)
			return err
		}
	}
	return nil
}
