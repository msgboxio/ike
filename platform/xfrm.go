// +build linux

package platform

import (
	"encoding/json"
	"net"
	"syscall"

	"github.com/msgboxio/log"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// src & dst are tunnel endpoints; ignored for transport mode
func makeTemplate(src, dst net.IP, reqId int, isTransportMode bool) netlink.XfrmPolicyTmpl {
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
		Reqid: reqId,
	}
}

func makeSaPolicies(reqId, priority int, sa *SaParams) (policies []*netlink.XfrmPolicy) {
	// initiator
	iniP := &netlink.XfrmPolicy{
		Src:     sa.IniNet,
		Dst:     sa.ResNet,
		Proto:   0,
		SrcPort: sa.IniPort,
		DstPort: sa.ResPort,
		Dir:     netlink.XFRM_DIR_IN,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: priority,
	}
	iniT := makeTemplate(sa.Ini, sa.Res, reqId, sa.IsTransportMode)
	iniP.Tmpls = append(iniP.Tmpls, iniT)
	if sa.IsInitiator {
		iniP.Dir = netlink.XFRM_DIR_OUT
	}
	policies = append(policies, iniP)
	// responder
	resP := &netlink.XfrmPolicy{
		Src:     sa.ResNet,
		Dst:     sa.IniNet,
		Proto:   0,
		SrcPort: sa.ResPort,
		DstPort: sa.IniPort,
		Dir:     netlink.XFRM_DIR_OUT,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: priority,
	}
	if sa.IsInitiator {
		resP.Dir = netlink.XFRM_DIR_IN
	}
	resT := makeTemplate(sa.Res, sa.Ini, reqId, sa.IsTransportMode)
	resP.Tmpls = append(resP.Tmpls, resT)
	policies = append(policies, resP)
	if !sa.IsTransportMode {
		// fwd for local tunnel endpoint
		fwdP := iniP
		fwdT := iniT
		if sa.IsInitiator {
			fwdP = resP
			fwdT = resT
		}
		fwd := &netlink.XfrmPolicy{
			Src:      fwdP.Src,
			Dst:      fwdP.Dst,
			Proto:    0,
			SrcPort:  fwdP.SrcPort,
			DstPort:  fwdP.DstPort,
			Dir:      netlink.XFRM_DIR_FWD,
			Priority: priority,
		}
		fwd.Tmpls = append(fwd.Tmpls, fwdT) // used same template
		policies = append(policies, fwd)
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
			Name:        "hmac(sha256)",
			Key:         sa.EspAi,
			TruncateLen: 128,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  sa.EspEi,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name:   "rfc4106(gcm(aes))",
		// 	Key:    sa.EspEi,
		// 	ICVLen: 256,
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
			Name:        "hmac(sha256)",
			Key:         sa.EspAr,
			TruncateLen: 128,
		},
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  sa.EspEr,
		},
		// Aead: &netlink.XfrmStateAlgo{
		// 	Name:   "rfc4106(gcm(aes))",
		// 	Key:    sa.EspEr,
		// 	ICVLen: 256,
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
	for _, policy := range makeSaPolicies(256, 16, sa) {
		log.V(3).Infof("adding Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			if err == syscall.EEXIST {
				err = errors.Errorf("Skipped adding policy %v because it already exists", policy)
			} else {
				err = errors.Errorf("Failed to add policy %v: %v", policy, err)
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
				err = errors.Errorf("Skipped adding state %v because it already exists", state)
			} else {
				statejs, _ := json.Marshal(state)
				err = errors.Errorf("Failed to add state %s: %v", string(statejs), err)
			}
			log.Errorf("%s", err)
			return err
		}
	}
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	for _, policy := range makeSaPolicies(256, 16, sa) {
		log.V(3).Infof("removing Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyDel(policy); err != nil {
			return errors.Errorf("Failed to remove policy %v: %v", policy, err)
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.V(3).Infof("removing State: %+v", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateDel(state); err != nil {
			return errors.Errorf("Failed to remove state %+v: %v", state, err)
		}
	}
	return nil
}
