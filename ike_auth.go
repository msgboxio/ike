package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"time"

	"fmt"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// SendAuth creates IKE_AUTH messages
func AuthFromSession(o *Session) (*Message, error) {
	// proposal
	var prop []*protocol.SaProposal
	// part of signed octet
	var initB []byte
	if o.isInitiator {
		prop = ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, o.EspSpiI)
		// intiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		initB = o.initIb
	} else {
		prop = ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, o.EspSpiR)
		// responder's signed octet
		// initR | Ni | prf(sk_pr | IDr )
		initB = o.initRb
	}
	return makeAuth(
		&authParams{
			isInitiator:     o.isInitiator,
			isTransportMode: o.cfg.IsTransportMode,
			spiI:            o.IkeSpiI,
			spiR:            o.IkeSpiR,
			proposals:       prop,
			tsI:             o.cfg.TsI,
			tsR:             o.cfg.TsR,
			authenticator:   o.authLocal,
			lifetime:        o.cfg.Lifetime,
		}, initB, o.Logger)
}

// HandleAuthForSession currently supports signature authenticaiton using
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// RFC 7427 - Signature Authentication in IKEv2
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
func HandleAuthForSession(o *Session, m *Message) (err error) {
	if err = checkAuth(m, o.isInitiator); err != nil {
		return err
	}
	// authenticate peer
	var idP *protocol.IdPayload
	var initB []byte
	if o.isInitiator {
		initB = o.initRb
		idP = m.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	} else {
		initB = o.initIb
		idP = m.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	}
	authP := m.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		o.Logger.Log("msg", "Ike Auth", "SHARED_KEY", string(idP.Data))
		return o.authRemote.Verify(initB, idP, authP.Data, o.Logger)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		chain, err := m.Payloads.GetCertchain()
		if err != nil {
			return err
		}
		cert := FormatCert(chain[0])
		o.Logger.Log("msg", "Ike Auth", "PEER_CERT", cert.String())
		// ensure key used to compute a digital signature belongs to the name in the ID payload
		if bytes.Compare(idP.Data, chain[0].RawSubject) != 0 {
			return errors.Errorf("Incorrect id in certificate: %s", hex.Dump(chain[0].RawSubject))
		}
		// find authenticator
		certAuth, ok := o.authRemote.(*CertAuthenticator)
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
		return certAuth.Verify(initB, idP, authP.Data, o.Logger)
	default:
		return errors.Errorf("Auth method not supported: %s", authP.AuthMethod)
	}
}

func HandleSaForSession(o *Session, m *Message) error {
	params, err := parseSa(m)
	if err != nil {
		return err
	}
	for _, n := range m.Payloads.GetNotifications() {
		if nErr, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
			// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE etc
			// TODO - for now, we should simply end the IKE_SA
			return errors.Errorf("peer notified: %s;", nErr)
		}
	}
	// level.Debug(o.Logger).Log("proposal", spew.Sprintf("%#v", params), "err", err)
	if err = o.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		return err
	}
	// TODO - check selector
	o.Logger.Log("cfg_selectors:", fmt.Sprintf("[INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR))
	o.Logger.Log("offered_selectors:", fmt.Sprintf("[INI]%s<=>%s[RES]", params.tsI, params.tsR))
	// message looks OK
	if o.isInitiator {
		if params.isResponse {
			o.EspSpiR = append([]byte{}, params.spiR...)
		}
		if o.EspSpiR == nil {
			err = errors.New("Missing responder SPI")
		}
	} else {
		if !params.isResponse {
			o.EspSpiI = append([]byte{}, params.spiI...)
		}
		if o.EspSpiI == nil {
			err = errors.New("Missing initiator SPI")
		}
	}
	if err != nil {
		return err
	}
	// start Lifetime timer
	if params.lifetime != 0 {
		reauth := params.lifetime - 2*time.Second
		if params.lifetime <= 2*time.Second {
			reauth = 0
		}
		o.Logger.Log("Lifetime", params.lifetime, "reauth_in", reauth)
		// TODO - start alarm for reauth
		// time.AfterFunc(reauth, func() {
		// 	o.Logger.Log("Lifetime Expired")
		// 	o.PostEvent(&state.StateEvent{Event: state.REKEY_START})
		// })
	}
	// transport mode
	if params.isTransportMode && o.cfg.IsTransportMode {
		o.Logger.Log("msg", "Using Transport Mode")
	} else {
		if params.isTransportMode {
			o.Logger.Log("msg", "Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			return errors.New("Peer Rejected Transport Mode Config")
		}
	}
	return nil
}
