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
		certId, ok := id.(*CertIdentity)
		if !ok {
			// should never happen
			return nil, errors.New("missing Certificate Identity")
		}
		if certId.Certificate == nil {
			return nil, errors.New("missing Certificate")
		}
		authMsg.Payloads.Add(&protocol.CertPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			CertEncodingType: protocol.X_509_CERTIFICATE_SIGNATURE,
			Data:             certId.Certificate.Raw,
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

func handleAuthForSession(sess *Session, msg *Message) (spi protocol.Spi, lt time.Duration, err error) {
	// can we authenticate ?
	if err = authenticateSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(protocol.ERR_AUTHENTICATION_FAILED)
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
	if err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
	}
	return
}

// authenticateSession supports signature authentication using
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// RFC 7427 - Signature Authentication in IKEv2
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
func authenticateSession(sess *Session, msg *Message) (err error) {
	if err := msg.CheckFlags(); err != nil {
		return err
	}
	if err = checkAuth(msg, sess.isInitiator); err != nil {
		return err
	}
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
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		// find authenticator
		pskAuth, ok := sess.authRemote.(*PskAuthenticator)
		if !ok {
			return errors.New("PreShared Key authentication is required")
		}
		return pskAuth.Verify(initB, idP, authP.Data, nil, sess.Logger)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		chain, err := msg.Payloads.GetCertchain()
		if err != nil {
			return err
		}
		// find authenticator
		certAuth, ok := sess.authRemote.(*CertAuthenticator)
		if !ok {
			return errors.New("Certificate authentication is required")
		}
		return certAuth.Verify(initB, idP, authP.Data, chain, sess.Logger)
	default:
		return errors.Errorf("Authentication method is not supported: %s", authP.AuthMethod)
	}
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
