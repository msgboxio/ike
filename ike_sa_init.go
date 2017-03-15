package ike

import (
	"bytes"
	"net"

	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var errMissingCookie = errors.New("Missing COOKIE")

// InitFromSession creates IKE_SA_INIT messages
func InitFromSession(o *Session) *Message {
	nonce := o.tkm.Nr
	if o.isInitiator {
		nonce = o.tkm.Ni
	}
	return makeInit(&initParams{
		isInitiator:       o.isInitiator,
		spiI:              o.IkeSpiI,
		spiR:              o.IkeSpiR,
		proposals:         ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.IkeSpiI),
		cookie:            o.responderCookie,
		dhTransformId:     o.tkm.suite.DhGroup.TransformId(),
		dhPublic:          o.tkm.DhPublic,
		nonce:             nonce,
		rfc7427Signatures: o.cfg.AuthMethod == protocol.AUTH_DIGITAL_SIGNATURE,
	})
}

// CheckInitRequest checks IKE_SA_INIT requests
func CheckInitRequest(cfg *Config, init *initParams, remote net.Addr) error {
	if !init.isInitiator {
		return protocol.ERR_INVALID_SYNTAX
	}
	// did we get a COOKIE ?
	if cookie := init.cookie; cookie != nil {
		// is COOKIE correct ?
		if !bytes.Equal(cookie, getCookie(init.nonce, init.spiI, remote)) {
			return errors.Wrap(errMissingCookie, "invalid cookie")
		}
	} else if cfg.ThrottleInitRequests {
		return errors.Wrap(errMissingCookie, "requesting cookie")
	}
	// check if transforms are usable
	// make sure dh tranform id is the one that was configured
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != init.dhTransformId {
		return errors.Wrapf(protocol.ERR_INVALID_KE_PAYLOAD,
			"Using different DH transform [%s] vs the one configured [%s]",
			init.dhTransformId, dh)
	}
	// check ike proposal
	if err := cfg.CheckProposals(protocol.IKE, init.proposals); err != nil {
		return err
	}
	return nil
}

func InitErrorNeedsReply(init *initParams, config *Config, remote net.Addr, err error) *Message {
	// send INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	switch cause := errors.Cause(err); cause {
	case protocol.ERR_INVALID_KE_PAYLOAD:
		tid := config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
		return NotificationResponse(init.spiI, protocol.INVALID_KE_PAYLOAD, tid)
	case errMissingCookie:
		// ask peer to send cookie
		return NotificationResponse(init.spiI, protocol.COOKIE, getCookie(init.nonce, init.spiI, remote))
	}
	return nil
}

func CheckInitResponseForSession(o *Session, init *initParams) error {
	if init.isInitiator { // id must be zero
		return protocol.ERR_INVALID_SYNTAX
	}
	// make sure responder spi is not the same as initiator spi
	if bytes.Equal(init.spiR, init.spiI) {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	// handle INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	for _, notif := range init.ns {
		switch notif.NotificationType {
		case protocol.COOKIE:
			return PeerRequestsCookieError{notif}
		case protocol.INVALID_KE_PAYLOAD:
			// TODO - handle properly
			return protocol.ERR_INVALID_KE_PAYLOAD
		case protocol.NO_PROPOSAL_CHOSEN:
			return protocol.ERR_NO_PROPOSAL_CHOSEN
		}
	}
	// make sure responder spi is set
	// in case messages are being reflected - TODO
	if SpiToInt64(init.spiR) == 0 {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	return nil
}

// return error secure signatures are configured, but not proposed by peer
func checkSignatureAlgo(o *Session, isEnabled bool) error {
	if !isEnabled {
		level.Warn(o.Logger).Log("msg", "Not using secure signatures")
		if o.cfg.AuthMethod == protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE {
			return errors.New("Peer is not using secure signatures")
		}
	}
	return nil
}

// HandleInitForSession expects the message given to it to be well formatted
func HandleInitForSession(o *Session, init *initParams, m *Message) error {
	// process notifications
	// check NAT-T payload to determine if there is a NAT between the two peers
	var rfc7427Signatures = false
	for _, ns := range init.ns {
		switch ns.NotificationType {
		case protocol.SIGNATURE_HASH_ALGORITHMS:
			o.Logger.Log("secure", protocol.AUTH_DIGITAL_SIGNATURE)
			rfc7427Signatures = true
		case protocol.NAT_DETECTION_DESTINATION_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), init.spiI, init.spiR, m.LocalAddr) {
				o.Logger.Log("HOST_NAT", m.LocalAddr)
			}
		case protocol.NAT_DETECTION_SOURCE_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), init.spiI, init.spiR, m.RemoteAddr) {
				o.Logger.Log("PEER_NAT", m.RemoteAddr)
			}
		}
	}
	// returns error if secure signatures are configured, but not proposed by peer
	if err := checkSignatureAlgo(o, rfc7427Signatures); err != nil {
		return err
	}
	if err := o.CreateIkeSa(init.nonce, init.dhPublic, init.spiI, init.spiR); err != nil {
		return err
	}
	// TODO
	// If there is NAT , then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// MUTATION
	// save Data
	if o.isInitiator {
		o.initRb = m.Data
	} else {
		o.initIb = m.Data
	}
	return nil
}
