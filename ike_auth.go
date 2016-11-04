package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/pkg/errors"
)

type authParams struct {
	isInitiator     bool
	isTransportMode bool
	spiI, spiR      protocol.Spi
	proposals       []*protocol.SaProposal
	tsI, tsR        []*protocol.Selector
	authenticator   Authenticator
	lifetime        time.Duration
}

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
// signed1 : init[i/r]B | N[r/i]
func makeAuth(params *authParams, initB []byte) *Message {
	// spiI, spiR protocol.Spi, proposals []*protocol.SaProposal, tsI, tsR []*protocol.Selector, signed1 []byte, tkm *Tkm, isTransportMode bool) *Message {
	flags := protocol.RESPONSE
	idPayloadType := protocol.PayloadTypeIDr
	if params.isInitiator {
		flags = protocol.INITIATOR
		idPayloadType = protocol.PayloadTypeIDi
	}
	auth := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         params.spiI,
			SpiR:         params.spiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_AUTH,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	id := params.authenticator.Identity()
	switch params.authenticator.AuthMethod() {
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		certId, ok := id.(*CertIdentity)
		if !ok {
			// should never happen
			panic("Logic Error")
		}
		if certId.Certificate == nil {
			log.Error("missing cert")
			return nil
		}
		auth.Payloads.Add(&protocol.CertPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			CertEncodingType: protocol.X_509_CERTIFICATE_SIGNATURE,
			Data:             certId.Certificate.Raw,
		})
	}
	iDp := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		IdPayloadType: idPayloadType,
		IdType:        id.IdType(),
		Data:          id.Id(),
	}
	auth.Payloads.Add(iDp)
	signature, err := params.authenticator.Sign(initB, iDp)
	if err != nil {
		log.Error(err)
		return nil
	}
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    params.authenticator.AuthMethod(),
		Data:          signature,
	})
	auth.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     params.proposals,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
		Selectors:                  params.tsI,
	})
	auth.Payloads.Add(&protocol.TrafficSelectorPayload{
		PayloadHeader:              &protocol.PayloadHeader{},
		TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
		Selectors:                  params.tsR,
	})
	// check for transport mode config
	if params.isTransportMode {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if params.isInitiator {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType: protocol.INITIAL_CONTACT,
		})
	}
	if !params.isInitiator && params.lifetime != 0 {
		auth.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType:    protocol.AUTH_LIFETIME,
			NotificationMessage: params.lifetime,
		})
	}
	return auth
}

// SendAuth callback from state machine
func AuthFromSession(o *Session) *Message {
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
		}, initB)
}

// TODO:
// currently support for signature authenticaiton is limited to
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// &
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
// TODO: RFC 7427 - Signature Authentication in IKEv2

// authenticates peer
func authenticate(o *Session, msg *Message) error {
	var idP *protocol.IdPayload
	var initB []byte
	if o.isInitiator {
		initB = o.initRb
		idP = msg.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	} else {
		initB = o.initIb
		idP = msg.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	}
	authP := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		return o.authRemote.Verify(initB, idP, authP.Data)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		chain, err := msg.Payloads.GetCertchain()
		if err != nil {
			return err
		}
		cert := FormatCert(chain[0])
		if log.V(2) {
			log.Infof(o.Tag()+"Ike Auth: PEER CERT: %+v", cert)
		}
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
			return errors.Errorf("Unable to verify certificate: %s", err)
		}
		// ensure that ID in cert is authorized
		if !MatchNameFromCert(&cert, certID.Name) {
			return errors.Errorf("Certificate is not Authorized for Name: %s", certID.Name)
		}
		// verify signature
		certAuth.SetUserCertificate(chain[0])
		return certAuth.Verify(initB, idP, authP.Data)
	default:
		return errors.Errorf("Auth method not supported: %s", authP.AuthMethod)
	}
}

func HandleAuthForSession(o *Session, m *Message) error {
	payloads := AuthIPayloads
	if o.isInitiator {
		payloads = AuthRPayloads
	}
	if err := m.EnsurePayloads(payloads); err != nil {
		for _, n := range m.Payloads.GetNotifications() {
			if nErr, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
				// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE etc
				// TODO - for now, we should simply end the IKE_SA
				return errors.Errorf("peer notifying : auth succeeded, but child sa was not created: %s", nErr)
			}
		}
		return err
	}
	// authenticate peer
	if err := authenticate(o, m); err != nil {
		log.Infof(o.Tag()+"IKE Auth Failed: %+v", err)
		return protocol.ERR_AUTHENTICATION_FAILED
	}
	log.V(1).Info(o.Tag() + "IKE SA AUTHENTICATED")
	return nil
}
