// +build linux

package platform

import (
	"encoding/json"
	"fmt"
	"net"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// src & dst are tunnel endpoints; ignored for transport mode
func makeTemplate(src, dst net.IP, reqId int32, isTransportMode bool) netlink.XfrmPolicyTmpl {
	mode := netlink.XFRM_MODE_TUNNEL
	if isTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
		src = net.IPv4zero
		dst = net.IPv4zero
	}
	return netlink.XfrmPolicyTmpl{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Reqid: int(reqId),
	}
}

func makeSaPolicies(reqId, priority int32, pol *protocol.PolicyParams, forInitiator bool) (policies []*netlink.XfrmPolicy) {
	// initiator
	iniP := &netlink.XfrmPolicy{
		Src:     pol.IniNet,
		Dst:     pol.ResNet,
		Proto:   0,
		SrcPort: pol.IniPort,
		DstPort: pol.ResPort,
		Dir:     netlink.XFRM_DIR_IN,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: int(priority),
	}
	iniT := makeTemplate(pol.Ini, pol.Res, reqId, pol.IsTransportMode)
	iniP.Tmpls = append(iniP.Tmpls, iniT)
	if forInitiator {
		iniP.Dir = netlink.XFRM_DIR_OUT
	}
	policies = append(policies, iniP)
	// responder
	resP := &netlink.XfrmPolicy{
		Src:     pol.ResNet,
		Dst:     pol.IniNet,
		Proto:   0,
		SrcPort: pol.ResPort,
		DstPort: pol.IniPort,
		Dir:     netlink.XFRM_DIR_OUT,
		// Mark: &netlink.XfrmMark{
		// Value: 0xabff22,
		// Mask:  0xffffffff,
		// },
		Priority: int(priority),
	}
	if forInitiator {
		resP.Dir = netlink.XFRM_DIR_IN
	}
	resT := makeTemplate(pol.Res, pol.Ini, reqId, pol.IsTransportMode)
	resP.Tmpls = append(resP.Tmpls, resT)
	policies = append(policies, resP)
	if !pol.IsTransportMode {
		// fwd for local tunnel endpoint
		fwdP := iniP
		fwdT := iniT
		if forInitiator {
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
			Priority: int(priority),
		}
		fwd.Tmpls = append(fwd.Tmpls, fwdT) // used same template
		policies = append(policies, fwd)
	}
	return policies
}

func addKeys(sa *SaParams, auth, crypt, aead *netlink.XfrmStateAlgo, forInitiator bool) {
	if auth != nil {
		auth.Key = sa.EspAr
		if forInitiator {
			auth.Key = sa.EspAi
		}
	}
	if crypt != nil {
		crypt.Key = sa.EspEr
		if forInitiator {
			crypt.Key = sa.EspEi
		}
	}
	if aead != nil {
		aead.Key = sa.EspEr
		if forInitiator {
			aead.Key = sa.EspEi
		}
	}
}

func encrTransform(tr *protocol.SaTransform) (crypt, aead *netlink.XfrmStateAlgo) {
	switch protocol.EncrTransformId(tr.Transform.TransformId) {
	case protocol.AEAD_AES_GCM_16:
		return nil, &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			ICVLen: 128, // only 16 octet ICV is supported
		}
	case protocol.AEAD_CHACHA20_POLY1305:
		return nil, &netlink.XfrmStateAlgo{
			Name:   "rfc7539esp(chacha20,poly1305)",
			ICVLen: 128, // icv is always 16 octets
		}
	case protocol.ENCR_AES_CBC:
		return &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
		}, nil
	}
	return
}

func authTransform(tr *protocol.SaTransform) (auth *netlink.XfrmStateAlgo) {
	switch protocol.AuthTransformId(tr.Transform.TransformId) {
	case protocol.AUTH_HMAC_SHA1_96:
		return &netlink.XfrmStateAlgo{
			Name:        "hmac(sha1)",
			TruncateLen: 96,
		}
	case protocol.AUTH_HMAC_SHA2_256_128:
		return &netlink.XfrmStateAlgo{
			Name:        "hmac(sha256)",
			TruncateLen: 128,
		}
	case protocol.AUTH_HMAC_SHA2_384_192:
		return &netlink.XfrmStateAlgo{
			Name:        "hmac(sha384)",
			TruncateLen: 192,
		}
	case protocol.AUTH_HMAC_SHA2_512_256:
		return &netlink.XfrmStateAlgo{
			Name:        "hmac(sha512)",
			TruncateLen: 256,
		}
	}
	return
}

func espTransforms(sa *SaParams, forInitiator bool) (auth, crypt, aead *netlink.XfrmStateAlgo) {
	for ttype, transform := range sa.EspTransforms {
		switch ttype {
		case protocol.TRANSFORM_TYPE_ENCR:
			crypt, aead = encrTransform(transform)
		case protocol.TRANSFORM_TYPE_INTEG:
			auth = authTransform(transform)
		}
	}
	addKeys(sa, auth, crypt, aead, forInitiator)
	return
}

func makeSaStates(reqid int32, sa *SaParams) (states []*netlink.XfrmState) {
	mode := netlink.XFRM_MODE_TUNNEL
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
	}
	// initiator
	authI, cryptI, aeadI := espTransforms(sa, true)
	initiator := &netlink.XfrmState{
		Src:   sa.Ini,
		Dst:   sa.Res,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Spi:   sa.SpiR,
		Reqid: int(reqid),
		Auth:  authI,
		Crypt: cryptI,
		Aead:  aeadI,
	}
	if sa.IniPort != 0 && sa.ResPort != 0 {
		initiator.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.IniPort,
			DstPort: sa.ResPort,
		}
	}
	states = append(states, initiator)
	// responder
	authR, cryptR, aeadR := espTransforms(sa, false)
	responder := &netlink.XfrmState{
		Src:   sa.Res,
		Dst:   sa.Ini,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  mode,
		Spi:   sa.SpiI,
		Reqid: int(reqid),
		Auth:  authR,
		Crypt: cryptR,
		Aead:  aeadR,
	}
	if sa.IniPort != 0 && sa.ResPort != 0 {
		responder.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.ResPort,
			DstPort: sa.IniPort,
		}
	}
	if sa.EspTransforms.GetType(protocol.TRANSFORM_TYPE_ESN).TransformId == uint16(protocol.ESN) {
		initiator.ReplayWindow = 256
		initiator.ESN = true
		responder.ReplayWindow = 256
		responder.ESN = true
	}
	states = append(states, responder)
	return
}

// public methods

func InstallPolicy(reqID int32, pol *protocol.PolicyParams, log log.Logger, forInitiator bool) error {
	for _, policy := range makeSaPolicies(reqID, 16, pol, forInitiator) {
		level.Debug(log).Log("INSTALL_POLICY", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			if err == syscall.EEXIST {
				log.Log("POLICY", fmt.Sprintf("Skipped adding %v: already exists", policy))
				continue
			} else {
				err = errors.Errorf("Failed to add policy %v: %v", policy, err)
			}
			return err
		}
	}
	return nil
}

func RemovePolicy(reqID int32, pol *protocol.PolicyParams, log log.Logger, forInitiator bool) error {
	for _, policy := range makeSaPolicies(reqID, 16, pol, forInitiator) {
		level.Debug(log).Log("REMOVE_POLICY", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyDel(policy); err != nil {
			return errors.Errorf("Failed to remove policy %v: %v", policy, err)
		}
	}
	return nil
}

func InstallChildSa(reqID int32, sa *SaParams, log log.Logger) error {
	for _, state := range makeSaStates(reqID, sa) {
		level.Debug(log).Log("ADD_STATE", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateAdd(state); err != nil {
			if err == syscall.EEXIST {
				// this should never happen
				err = errors.Errorf("Skipped adding state %v because it already exists", state)
			} else {
				statejs, _ := json.Marshal(state)
				err = errors.Errorf("Failed to add state %s: %v", string(statejs), err)
			}
			return err
		}
	}
	return nil
}

func RemoveChildSa(reqID int32, sa *SaParams, log log.Logger) error {
	for _, state := range makeSaStates(reqID, sa) {
		level.Debug(log).Log("REMOVE_STATE", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateDel(state); err != nil {
			return errors.Errorf("Failed to remove state %+v: %v", state, err)
		}
	}
	return nil
}
