// +build linux

package platform

import (
	"encoding/json"
	"net"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/protocol"
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
			ICVLen: int(tr.KeyLength),
		}
	case protocol.AEAD_CHACHA20_POLY1305:
		return nil, &netlink.XfrmStateAlgo{
			Name:   "rfc7539esp(chacha20,poly1305)",
			ICVLen: 128,
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

func makeSaStates(reqid int, sa *SaParams) (states []*netlink.XfrmState) {
	mode := netlink.XFRM_MODE_TUNNEL
	if sa.IsTransportMode {
		mode = netlink.XFRM_MODE_TRANSPORT
	}
	// initiator
	authI, cryptI, aeadI := espTransforms(sa, true)
	initiator := &netlink.XfrmState{
		Src:          sa.Ini,
		Dst:          sa.Res,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
		Spi:          sa.SpiR,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth:         authI,
		Crypt:        cryptI,
		Aead:         aeadI,
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
		Src:          sa.Res,
		Dst:          sa.Ini,
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         mode,
		Spi:          sa.SpiI,
		Reqid:        reqid,
		ReplayWindow: 32,
		Auth:         authR,
		Crypt:        cryptR,
		Aead:         aeadR,
	}
	if sa.IniPort != 0 && sa.ResPort != 0 {
		responder.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: sa.ResPort,
			DstPort: sa.IniPort,
		}
	}
	states = append(states, responder)
	return
}

func InstallChildSa(sa *SaParams, log *logrus.Logger) error {
	for _, policy := range makeSaPolicies(256, 16, sa) {
		log.Debugf("adding Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			if err == syscall.EEXIST {
				err = errors.Errorf("Skipped adding policy %v because it already exists", policy)
			} else {
				err = errors.Errorf("Failed to add policy %v: %v", policy, err)
			}
			return err
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.Debugf("adding State: %+v", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateAdd(state); err != nil {
			if err == syscall.EEXIST {
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

func RemoveChildSa(sa *SaParams, log *logrus.Logger) error {
	for _, policy := range makeSaPolicies(256, 16, sa) {
		log.Debugf("removing Policy: %+v", policy)
		// create xfrm policy rules
		if err := netlink.XfrmPolicyDel(policy); err != nil {
			return errors.Errorf("Failed to remove policy %v: %v", policy, err)
		}
	}
	for _, state := range makeSaStates(256, sa) {
		log.Debugf("removing State: %+v", state)
		// crate xfrm state rules
		if err := netlink.XfrmStateDel(state); err != nil {
			return errors.Errorf("Failed to remove state %+v: %v", state, err)
		}
	}
	return nil
}
