package ike

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// authFromSession creates IKE_AUTH messages
func authFromSession(sess *Session) (*Message, error) {
	// proposal
	var prop protocol.Proposals
	// part of signed octet
	var initB []byte
	var idPayloadType protocol.PayloadType
	if sess.isInitiator {
		prop = protocol.ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiI)
		// initiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		initB = sess.initIb
		idPayloadType = protocol.PayloadTypeIDi
	} else {
		prop = protocol.ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiR)
		// responder's signed octet
		// initR | Ni | prf(sk_pr | IDr )
		initB = sess.initRb
		idPayloadType = protocol.PayloadTypeIDr
	}
	authMsg := makeAuth(
		&authParams{
			isInitiator:     sess.isInitiator,
			isTransportMode: sess.cfg.IsTransportMode,
			spiI:            sess.IkeSpiI,
			spiR:            sess.IkeSpiR,
			proposals:       prop,
			tsI:             sess.cfg.TsI,
			tsR:             sess.cfg.TsR,
			lifetime:        sess.cfg.Lifetime,
		})
	id := sess.authLocal.Identity()
	// add CERT
	switch id.AuthMethod() {
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		certID, ok := id.(*CertIdentity)
		if !ok {
			// should never happen
			return nil, errors.New("missing Certificate Identity")
		}
		if certID.Certificate == nil {
			return nil, errors.New("missing Certificate")
		}
		authMsg.Payloads.Add(&protocol.CertPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			CertEncodingType: protocol.X_509_CERTIFICATE_SIGNATURE,
			Data:             certID.Certificate.Raw,
		})
	}
	// add ID
	iDp := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		IdPayloadType: idPayloadType,
		IdType:        id.IdType(),
		Data:          id.Id(),
	}
	authMsg.Payloads.Add(iDp)
	// signature
	signature, err := sess.authLocal.Sign(initB, iDp, sess.Logger)
	if err != nil {
		return nil, err
	}
	authMsg.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    id.AuthMethod(),
		Data:          signature,
	})
	return authMsg, nil
}

// auth respones can be a valid auth message, auth resp with AUTHENTICATION_FAILED
// or INFORMATIONAL with AUTHENTICATION_FAILED
func checkAuthResponseForSession(sess *Session, msg *Message) (err error) {
	// check if reply
	if err = msg.CheckFlags(); err != nil {
		return
	}
	// other flag combos have been checked
	if !msg.IkeHeader.Flags.IsResponse() {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: unexpected request")
	}
	// is an INFORMATIONAL ERROR
	if msg.IkeHeader.ExchangeType == protocol.INFORMATIONAL {
		// expect it to be this
		return errors.Wrap(errPeerRemovedIkeSa, "IKE_AUTH: INFORMATIONAL AUTHENTICATION_FAILED")
	}
	// must be an AUTH message
	if msg.IkeHeader.ExchangeType != protocol.IKE_AUTH {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: incorrect type")
	}
	// ensure other payloads are present
	if err = msg.EnsurePayloads(authRPayloads); err != nil {
		// not a proper AUTH response
		// check for NOTIFICATION : AUTHENTICATION_FAILED
		for _, n := range msg.Payloads.GetNotifications() {
			if n.NotificationType == protocol.AUTHENTICATION_FAILED {
				err = errors.Wrap(errPeerRemovedIkeSa, "IKE_AUTH: response AUTHENTICATION_FAILED")
				return
			}
		}
	}
	return
}

func checkAuthRequestForSession(sess *Session, msg *Message) (err error) {
	// must be a request
	if err = msg.CheckFlags(); err != nil {
		return err
	}
	if msg.IkeHeader.Flags.IsResponse() {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: responder received response")
	}
	// must be an AUTH message
	if msg.IkeHeader.ExchangeType != protocol.IKE_AUTH {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: incorrect type")
	}
	// ensure other payloads are present
	if err := msg.EnsurePayloads(authIPayloads); err != nil {
		return err
	}
	return nil
}

func handleAuthForSession(sess *Session, msg *Message) (spi protocol.Spi, lt time.Duration, err error) {
	// can we authenticate ?
	if err = authenticateSession(sess, msg); err != nil {
		err = errors.Wrap(protocol.ERR_AUTHENTICATION_FAILED, err.Error())
		return
	}
	for _, n := range msg.Payloads.GetNotifications() {
		if nErr, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
			// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE etc
			// TODO - for now, we should simply end the IKE_SA
			err = errors.Wrap(nErr, "peer notified")
			return
		}
	}
	// are SA parameters ok?
	params, err := parseSaAndSelectors(msg)
	if err != nil {
		return
	}
	spi, lt, err = checkSelectorsForSession(sess, params)
	return
}

func authenticateSession(sess *Session, msg *Message) (err error) {
	// authenticate peer
	var idP *protocol.IdPayload
	var initB []byte
	if sess.isInitiator {
		initB = sess.initRb
		idP = msg.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	} else {
		initB = sess.initIb
		idP = msg.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	}
	authP := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	chain, err := msg.Payloads.GetCertchain()
	if err != nil {
		return err
	}
	return sess.authPeer.Verify(initB, idP, authP.AuthMethod, authP.Data, chain, sess.Logger)
}

// checkSelectorsForSession returns Peer Spi
func checkSelectorsForSession(sess *Session, params *authParams) (spi protocol.Spi, lt time.Duration, err error) {
	if err = sess.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		sess.Logger.Log("BAD_PROPOSAL", err,
			"PEER", spew.Sprintf("%#v", params.proposals),
			"OUR", spew.Sprintf("%#v", sess.cfg.ProposalEsp))
		return
	}
	// selectors
	if err = sess.cfg.CheckSelectors(params.tsI, params.tsR, params.isTransportMode); err != nil {
		sess.Logger.Log("BAD_SELECTORS", err,
			"PEER", fmt.Sprintf("[INI]%s<=>%s[RES]", params.tsI, params.tsR),
			"OUR_SELECTORS", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR))
		return
	}
	// message looks OK
	if sess.isInitiator {
		spi = append([]byte{}, params.spiR...)
	} else {
		spi = append([]byte{}, params.spiI...)
	}
	lt = params.lifetime
	log := []interface{}{"SELECTORS", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR)}
	if params.lifetime != 0 {
		log = append(log, "LIFETIME", params.lifetime)
	}
	if params.isTransportMode {
		log = append(log, "MODE", "TRANSPORT")
	} else {
		log = append(log, "MODE", "TUNNEL")
	}
	sess.Logger.Log(log...)
	return
}
