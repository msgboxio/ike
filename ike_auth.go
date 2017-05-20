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
	if sess.isInitiator {
		prop = protocol.ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiI)
		// initiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		initB = sess.initIb
	} else {
		prop = protocol.ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiR)
		// responder's signed octet
		// initR | Ni | prf(sk_pr | IDr )
		initB = sess.initRb
	}
	return makeAuth(
		&authParams{
			isInitiator:     sess.isInitiator,
			isTransportMode: sess.cfg.IsTransportMode,
			spiI:            sess.IkeSpiI,
			spiR:            sess.IkeSpiR,
			proposals:       prop,
			tsI:             sess.cfg.TsI,
			tsR:             sess.cfg.TsR,
			lifetime:        sess.cfg.Lifetime,
		}, sess.authLocal, initB, sess.Logger)
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
		sess.Logger.Log("PEER_PROPOSALS", spew.Sprintf("%#v", params.proposals))
		sess.Logger.Log("OUR_PROPOSALS", spew.Sprintf("%#v", sess.cfg.ProposalEsp))
		return
	}
	// selectors
	sess.Logger.Log("PEER_SELECTORS", fmt.Sprintf("[INI]%s<=>%s[RES]", params.tsI, params.tsR))
	if err = sess.cfg.CheckSelectors(params.tsI, params.tsR, params.isTransportMode); err != nil {
		sess.Logger.Log("OUR_SELECTORS", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR))
		return
	}
	if params.isTransportMode {
		sess.Logger.Log("MODE", "TRANSPORT")
	} else {
		sess.Logger.Log("MODE", "TUNNEL")
	}
	// message looks OK
	if sess.isInitiator {
		spi = append([]byte{}, params.spiR...)
	} else {
		spi = append([]byte{}, params.spiI...)
	}
	if err != nil {
		return
	}
	lt = params.lifetime
	if params.lifetime != 0 {
		sess.Logger.Log("LIFETIME", params.lifetime)
	}
	return
}
