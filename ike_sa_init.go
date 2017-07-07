package ike

import (
	"bytes"
	"net"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

//
// outgoing request
//

// InitFromSession creates IKE_SA_INIT messages
func InitFromSession(sess *Session) *Message {
	var prop protocol.Proposals
	nonce := sess.tkm.Nr
	if sess.isInitiator {
		prop = protocol.ProposalFromTransform(protocol.IKE, sess.cfg.ProposalIke, sess.IkeSpiI)
		nonce = sess.tkm.Ni
	} else {
		prop = protocol.ProposalFromTransform(protocol.IKE, sess.cfg.ProposalIke, sess.IkeSpiR)
	}
	return makeInit(&initParams{
		isInitiator:       sess.isInitiator,
		spiI:              sess.IkeSpiI,
		spiR:              sess.IkeSpiR,
		proposals:         prop,
		cookie:            sess.responderCookie,
		dhTransformID:     sess.tkm.suite.DhGroup.TransformId(),
		dhPublic:          sess.tkm.DhPublic,
		nonce:             nonce,
		rfc7427Signatures: sess.rfc7427Signatures,
		hasNat:            true,
	}, sess.Local, sess.Remote)
}

//
// incoming request
//

// checkInitRequest will handle sending cookie requests to the initiator
func checkInitRequest(msg *Message, conn Conn, config *Config, log log.Logger) error {
	if err := msg.CheckFlags(); err != nil {
		return err
	}
	init, err := parseInit(msg)
	if err != nil {
		return err
	}
	if err := _checkInitRequest(config, init, msg.RemoteAddr); err != nil {
		// handle errors that need reply: COOKIE or DH
		if reply := initErrorNeedsReply(init, config, msg.RemoteAddr, err); reply != nil {
			log.Log("INIT_REPLY", err.Error())
			WriteMessage(conn, reply, nil, false, log)
		}
		return err
	}
	msg.Params = init
	return nil
}

func _checkInitRequest(cfg *Config, init *initParams, remote net.Addr) error {
	if !init.isInitiator {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: request from responder")
	}
	// check SPI
	if SpiToInt64(init.spiI) == 0 {
		return errors.Wrap(protocol.ERR_INVALID_IKE_SPI, "IKE_SA_INIT: missing SPI")
	}
	// did we get a COOKIE ?
	if cookie := init.cookie; cookie != nil {
		// is COOKIE correct ?
		if !bytes.Equal(cookie, getCookie(init.nonce, init.spiI, remote)) {
			return errInvalidCookie
		}
	} else if cfg.ThrottleInitRequests {
		return errMissingCookie
	}
	// check if transforms are usable
	if err := cfg.CheckDhTransform(init.dhTransformID); err != nil {
		return err
	}
	// check ike proposal
	if err := cfg.CheckProposals(protocol.IKE, init.proposals); err != nil {
		return err
	}
	return nil
}

func initErrorNeedsReply(init *initParams, config *Config, remote net.Addr, err error) *Message {
	// send INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	switch cause := errors.Cause(err); cause {
	case protocol.ERR_INVALID_KE_PAYLOAD:
		tid := config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
		return notificationResponse(init.spiI, protocol.INVALID_KE_PAYLOAD, tid, remote)
	case protocol.ERR_NO_PROPOSAL_CHOSEN:
		return notificationResponse(init.spiI, protocol.NO_PROPOSAL_CHOSEN, nil, remote)
		// TODO - handle
	case errMissingCookie:
		// ask peer to send cookie
		return notificationResponse(init.spiI, protocol.COOKIE, getCookie(init.nonce, init.spiI, remote), remote)
	}
	return nil
}

func notificationResponse(spi protocol.Spi, nt protocol.NotificationType, data interface{}, remote net.Addr) *Message {
	msg := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         spi,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        protocol.RESPONSE,
		},
		Payloads:   protocol.MakePayloads(),
		RemoteAddr: remote,
	}
	msg.Payloads.Add(&protocol.NotifyPayload{
		PayloadHeader:       &protocol.PayloadHeader{},
		ProtocolId:          protocol.IKE,
		NotificationType:    nt,
		NotificationMessage: data,
	})
	return msg
}

//
// incoming response
//

func checkInitResponseForSession(sess *Session, msg *Message) error {
	init, err := parseInit(msg)
	if err != nil {
		return err
	}
	if init.isInitiator { // id must be zero
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: response from initiator")
	}
	// make sure responder spi is not the same as initiator spi
	if bytes.Equal(init.spiR, init.spiI) {
		return errors.Wrap(protocol.ERR_INVALID_IKE_SPI, "IKE_SA_INIT: invalid SPI")
	}
	// handle INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	for _, notif := range init.ns {
		switch notif.NotificationType {
		case protocol.COOKIE:
			return peerRequestsCookieError{notif}
		case protocol.INVALID_KE_PAYLOAD:
			// TODO - handle properly
			return errors.Wrap(protocol.ERR_INVALID_KE_PAYLOAD, "IKE_SA_INIT: peer returned")
		case protocol.NO_PROPOSAL_CHOSEN:
			return errors.Wrap(protocol.ERR_NO_PROPOSAL_CHOSEN, "IKE_SA_INIT: peer returned")
		}
	}
	// make sure responder spi is set
	// in case messages are being reflected - TODO
	if SpiToInt64(init.spiR) == 0 {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: invalid responder SPI")
	}
	// check if transforms are usable
	if err := sess.cfg.CheckDhTransform(init.dhTransformID); err != nil {
		return err
	}
	// check ike proposal
	if err := sess.cfg.CheckProposals(protocol.IKE, init.proposals); err != nil {
		return err
	}
	msg.Params = init
	return nil
}
