package ike

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type authParams struct {
	isInitiator     bool
	isTransportMode bool
	spiI, spiR      protocol.Spi
	proposals       []*protocol.SaProposal
	tsI, tsR        []*protocol.Selector
	Identity
	Authenticator
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
	switch params.Authenticator.AuthMethod() {
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		certId, ok := params.Identity.(*CertIdentity)
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
	iD := &protocol.IdPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		IdPayloadType: idPayloadType,
		IdType:        params.Identity.IdType(),
		Data:          params.Identity.Id(),
	}
	auth.Payloads.Add(iD)
	signature, err := params.Authenticator.Sign(initB, iD)
	if err != nil {
		log.Error(err)
		return nil
	}
	if params.Authenticator.AuthMethod() == protocol.AUTH_DIGITAL_SIGNATURE {
		certAuth := params.Authenticator.(*CertAuthenticator)
		sigAuth := &protocol.SignatureAuth{
			Asn1Data:  []byte(signatureAlgorithmToAsn1[certAuth.signatureAlgorithm]),
			Signature: signature,
		}
		signature = sigAuth.Encode()
	}
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    params.Authenticator.AuthMethod(),
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
	return auth
}

// SendAuth callback from state machine
func AuthFromSession(o *Session) *Message {
	// IKE_AUTH
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		log.Infoln(o.Tag() + "Adding host based selectors")
		// add host based selectors by default
		slen := len(o.local) * 8
		ini := o.remote
		res := o.local
		if o.isInitiator {
			ini = o.local
			res = o.remote
		}
		o.cfg.AddSelector(
			&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
			&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
	}
	log.Infof(o.Tag()+"SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
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
			o.isInitiator,
			o.cfg.IsTransportMode,
			o.IkeSpiI, o.IkeSpiR,
			prop, o.cfg.TsI, o.cfg.TsR,
			o.idLocal,
			authenticator(o.idLocal, o.tkm, o.rfc7427Signatures, o.isInitiator),
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
func authenticate(msg *Message, initB []byte, idP *protocol.IdPayload, authenticator Authenticator, idRemote Identity) error {
	authP := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		if err := authenticator.Verify(initB, idP, authP.Data); err != nil {
			return err
		}
		return nil
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		certP := msg.Payloads.Get(protocol.PayloadTypeCERT)
		if certP == nil {
			return errors.New("Ike Auth failed: certificate is required")
		}
		cert := certP.(*protocol.CertPayload)
		if cert.CertEncodingType != protocol.X_509_CERTIFICATE_SIGNATURE {
			return fmt.Errorf("Ike Auth failed: cert encoding not supported: %v", cert.CertEncodingType)
		}
		// cert.data is DER-encoded X.509 certificate
		x509Cert, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			return fmt.Errorf("Ike Auth failed: uanble to parse cert: %s", err)
		}
		rsaCertAuth := authenticator.(*CertAuthenticator)
		rsaCertAuth.SetUserCertificate(x509Cert)
		if authP.AuthMethod == protocol.AUTH_RSA_DIGITAL_SIGNATURE {
			// rsaCertAuth.signatureAlgorithm = x509.SHA1WithRSA // set by default
			if err := rsaCertAuth.Verify(initB, idP, authP.Data); err != nil {
				return err
			}
		} else { // AUTH_DIGITAL_SIGNATURE
			// further parse authP.Data
			sigAuth := &protocol.SignatureAuth{}
			if err := sigAuth.Decode(authP.Data); err != nil {
				return err
			}
			if method, ok := asnCertAuthTypes[string(sigAuth.Asn1Data)]; ok {
				rsaCertAuth.signatureAlgorithm = method
				if err := rsaCertAuth.Verify(initB, idP, sigAuth.Signature); err != nil {
					return fmt.Errorf("Ike Auth failed: with method %s, %s", method, err)
				}
			} else {
				return fmt.Errorf("Ike Auth failed: auth method not supported:\n%s", hex.Dump(sigAuth.Asn1Data))
			}
		}
		return nil
	default:
		return fmt.Errorf("Ike Auth failed: auth method not supported: %s", authP.AuthMethod)
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
				log.Warning(o.Tag() + "peer notifying : auth succeeded, but child sa was not created")
				// for example, due to FAILED_CP_REQUIRED, NO_PROPOSAL_CHOSEN etc
				// TODO - for now, we should simply end the IKE_SA
				return nErr
			}
		}
		return err
	}
	var idP *protocol.IdPayload
	var initB []byte
	if o.isInitiator {
		initB = o.initRb
		idP = m.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	} else {
		initB = o.initIb
		idP = m.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	}
	// authenticate peer
	authenticator := authenticator(o.idRemote, o.tkm, o.rfc7427Signatures, o.isInitiator)
	if err := authenticate(m, initB, idP, authenticator, o.idRemote); err != nil {
		log.Info(o.Tag() + err.Error())
		return protocol.ERR_AUTHENTICATION_FAILED
	}
	log.Info(o.Tag() + "IKE SA AUTHENTICATED")
	return nil
}
