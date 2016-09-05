// +build linux

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"

	"github.com/msgboxio/log"
	"github.com/msgboxio/netlink"
)

// Policy :
// selector
// list of templates
// index

// Template:
// mode,proto,algo:
// daddr/saddr: tunnel endpoint (ignored for transport mode)

// template & selector are used to match sa
// sa is applied

func makeSelector(src, dst *net.IPNet) *netlink.XfrmSelector {
	sel := &netlink.XfrmSelector{}
	sel.Family = uint16(netlink.GetIPFamily(dst.IP))
	sel.Daddr.FromIP(dst.IP)
	sel.Saddr.FromIP(src.IP)
	prefixlenD, _ := dst.Mask.Size()
	sel.PrefixlenD = uint8(prefixlenD)
	prefixlenS, _ := src.Mask.Size()
	sel.PrefixlenS = uint8(prefixlenS)
	return sel
}

// src & dst are tunnel endpoints; ignored for transport mode
func makeTemplate(src, dst net.IP, reqId uint32, isTransportMode bool) (templ netlink.XfrmPolicyTmpl) {
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

func makeSaPolicies(reqId uint32, sa *SaParams) (policies []netlink.XfrmPolicy) {
	// ini
	iniToRes := makeSelector(sa.IniNet, sa.ResNet)
	ini := netlink.XfrmPolicy{
		Sel:      iniToRes,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 1795,
	}
	ini.Tmpls = append(ini.Tmpls, makeTemplate(sa.Ini, sa.Res, reqId, sa.IsTransportMode))
	if sa.IsResponder {
		ini.Dir = netlink.XFRM_DIR_IN
	}
	policies = append(policies, ini)

	// responder
	resToIni := makeSelector(sa.ResNet, sa.IniNet)
	resp := netlink.XfrmPolicy{
		Sel:      resToIni,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 1795,
	}
	inTemplate := makeTemplate(sa.Res, sa.Ini, reqId, sa.IsTransportMode)
	if sa.IsResponder {
		resp.Dir = netlink.XFRM_DIR_OUT
	}
	resp.Tmpls = append(resp.Tmpls, inTemplate)
	policies = append(policies, resp)
	if !sa.IsTransportMode {
		// fwd ??
		fwdSel := resToIni
		if sa.IsResponder {
			fwdSel = iniToRes
		}
		fwd := netlink.XfrmPolicy{
			Sel:      fwdSel,
			Dir:      netlink.XFRM_DIR_FWD,
			Priority: 1795,
		}
		fwd.Tmpls = append(fwd.Tmpls, inTemplate)
		policies = append(policies, fwd)
	}
	return policies
}

func makeSaStates(reqid int, sa *SaParams) (states []netlink.XfrmState) {
	mode := netlink.XFRM_MODE_TUNNEL
	flag := netlink.XFRM_STATE_AF_UNSPEC
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
		flag = 0
	}
	out := netlink.XfrmState{
		Sel:          makeSelector(sa.IniNet, sa.ResNet),
		Src:          sa.Ini,
		Dst:          sa.Res,
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
	if sa.IniPort != 0 && sa.ResPort != 0 {
		out.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.IniPort,
			DstPort: sa.ResPort,
		}
	}
	states = append(states, out)
	in := netlink.XfrmState{
		Sel:          makeSelector(sa.ResNet, sa.IniNet),
		Src:          sa.Res,
		Dst:          sa.Ini,
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
	ns, err := netlink.GetNetlinkSocket(syscall.NETLINK_XFRM)
	if err != nil {
		return err
	}
	defer ns.Close()

	for _, policy := range makeSaPolicies(256, sa) {
		log.V(1).Infof("adding Policy: %+v", policy)
		// create xfrm policy rules
		err = netlink.XfrmPolicyAdd(ns, &policy)
		if err != nil {
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
		log.V(1).Infof("adding State: %+v", state)
		// crate xfrm state rules
		err = netlink.XfrmStateAdd(ns, &state)
		if err != nil {
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
