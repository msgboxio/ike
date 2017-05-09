package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// authFromSession creates IKE_AUTH messages
func authFromSession(sess *Session) (*Message, error) {
	// proposal
	var prop []*protocol.SaProposal
	// part of signed octet
	var initB []byte
	if sess.isInitiator {
		prop = ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiI)
		// initiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		initB = sess.initIb
	} else {
		prop = ProposalFromTransform(protocol.ESP, sess.cfg.ProposalEsp, sess.EspSpiR)
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
			authenticator:   sess.authLocal,
			lifetime:        sess.cfg.Lifetime,
		}, initB, sess.Logger)
}

func handleAuthForSession(sess *Session, msg *Message) (err error) {
	if err := msg.CheckFlags(); err != nil {
		return err
	}
	if err = authenticateSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		err = errors.Wrap(protocol.ERR_AUTHENTICATION_FAILED, err.Error())
		sess.CheckError(err)
		return
	}
	if err = handleSaForSession(sess, msg); err != nil {
		// send notification to peer & end IKE SA
		sess.CheckError(err)
		return
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
		sess.Logger.Log("AUTH", fmt.Sprintf("SHARED_KEY[%s]", string(idP.Data)))
		return sess.authRemote.Verify(initB, idP, authP.Data, sess.Logger)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		chain, err := msg.Payloads.GetCertchain()
		if err != nil {
			return err
		}
		cert := FormatCert(chain[0])
		sess.Logger.Log("AUTH", fmt.Sprintf("PEER_CERT[%s]", cert.String()))
		// ensure key used to compute a digital signature belongs to the name in the ID payload
		if bytes.Compare(idP.Data, chain[0].RawSubject) != 0 {
			return errors.Errorf("Incorrect id in certificate: %s", hex.Dump(chain[0].RawSubject))
		}
		// find authenticator
		certAuth, ok := sess.authRemote.(*CertAuthenticator)
		if !ok {
			return errors.New("Certificate authentication is required")
		}
		// find identity
		certID, ok := certAuth.identity.(*CertIdentity)
		if !ok {
			// should never happen
			panic("logic error")
		}
		// Verify validity of certificate
		opts := x509.VerifyOptions{
			Roots: certID.Roots,
		}
		if _, err := chain[0].Verify(opts); err != nil {
			return errors.Wrap(err, "Unable to verify certificate")
		}
		// ensure that ID in cert is authorized
		// TODO - is this reasonable?
		if !MatchNameFromCert(&cert, certID.Name) {
			return errors.Errorf("Certificate is not Authorized for Name: %s", certID.Name)
		}
		// verify signature
		certAuth.SetUserCertificate(chain[0])
		return certAuth.Verify(initB, idP, authP.Data, sess.Logger)
	default:
		return errors.Errorf("Auth method not supported: %s", authP.AuthMethod)
	}
}

// handleSaForSession handles the remaining tasks after authentication succeeded
func handleSaForSession(sess *Session, msg *Message) error {
	params, err := parseSa(msg)
	if err != nil {
		return err
	}
	for _, n := range msg.Payloads.GetNotifications() {
		if nErr, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
			// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE etc
			// TODO - for now, we should simply end the IKE_SA
			return errors.Errorf("peer notified: %s;", nErr)
		}
	}
	// level.Debug(o.Logger).Log("proposal", spew.Sprintf("%#v", params), "err", err)
	if err = sess.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		return errors.Wrap(protocol.ERR_INVALID_SELECTORS, err.Error())
	}
	// TODO - check selector
	sess.Logger.Log("cfg_selectors:", fmt.Sprintf("[INI]%s<=>%s[RES]", sess.cfg.TsI, sess.cfg.TsR))
	sess.Logger.Log("offered_selectors:", fmt.Sprintf("[INI]%s<=>%s[RES]", params.tsI, params.tsR))
	// message looks OK
	if sess.isInitiator {
		if params.isResponse {
			sess.EspSpiR = append([]byte{}, params.spiR...)
		}
		if sess.EspSpiR == nil {
			err = errors.Wrap(protocol.ERR_INVALID_KE_PAYLOAD, "Missing responder SPI")
		}
	} else {
		if !params.isResponse {
			sess.EspSpiI = append([]byte{}, params.spiI...)
		}
		if sess.EspSpiI == nil {
			err = errors.Wrap(protocol.ERR_INVALID_KE_PAYLOAD, "Missing initiator SPI")
		}
	}
	if err != nil {
		return err
	}
	if params.lifetime != 0 {
		sess.Logger.Log("Lifetime", params.lifetime)
		sess.cfg.Lifetime = params.lifetime
	}
	// transport mode
	if params.isTransportMode && sess.cfg.IsTransportMode {
		sess.Logger.Log("Mode", "TRANSPORT")
	} else {
		// one side wants tunnel mode
		if params.isTransportMode {
			sess.Logger.Log("Mode", "Peer Requested TRANSPORT, configured TUNNEL")
			return errors.Wrap(protocol.ERR_INVALID_SELECTORS, "Reject TRANSPORT Mode Request")
		} else if sess.cfg.IsTransportMode {
			sess.Logger.Log("Mode", "Peer Requested TUNNEL, configured TRANSPORT")
			return errors.Wrap(protocol.ERR_INVALID_SELECTORS, "Reject TUNNEL Mode Request")
		} else {
			sess.Logger.Log("Mode", "TUNNEL")
		}
	}
	return nil
}
