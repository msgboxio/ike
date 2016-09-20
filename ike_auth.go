package ike

import (
	"crypto/x509"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
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
	if params.Authenticator.AuthMethod() == protocol.AUTH_RSA_DIGITAL_SIGNATURE {
		certId, ok := params.Identity.(*RsaCertIdentity)
		if !ok {
			// should never happen
			panic("EEk")
		}
		if certId.Certificate == nil {
			log.Info("missing cert")
			return nil
		}
		if certId.PrivateKey == nil {
			log.Info("missing key")
			return nil
		}
		log.Info("sending cert")
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
	auth.Payloads.Add(&protocol.AuthPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		AuthMethod:    params.Authenticator.AuthMethod(),
		Data:          params.Authenticator.Sign(initB, iD, params.Identity),
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
func (o *Session) SendAuth() (s state.StateEvent) {
	// IKE_AUTH
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		log.Infoln("Adding host based selectors")
		// add host based selectors by default
		slen := len(o.local) * 8
		ini := o.remote
		res := o.local
		if o.tkm.isInitiator {
			ini = o.local
			res = o.remote
		}
		o.cfg.AddSelector(
			&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
			&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
	}
	log.Infof("SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)

	// proposal
	var prop []*protocol.SaProposal
	// part of signed octet
	var initB []byte
	if o.tkm.isInitiator {
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
	auth := makeAuth(
		&authParams{
			o.tkm.isInitiator,
			o.cfg.IsTransportMode,
			o.IkeSpiI, o.IkeSpiR,
			prop, o.cfg.TsI, o.cfg.TsR,
			o.idLocal,
			authenticator(o.idLocal, o.tkm),
		}, initB)
	if auth == nil {
		return state.StateEvent{
			Event: state.AUTH_FAIL,
			Data:  protocol.ERR_NO_PROPOSAL_CHOSEN,
		}
	}
	auth.IkeHeader.MsgId = o.msgId
	// encode
	return o.sendMsg(auth.Encode(o.tkm))
}

// TODO:
// currently support for signature authenticaiton is limited to
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// &
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
// AUTH_ECDSA_256                         AuthMethod = 9  // RFC4754
// AUTH_ECDSA_384                         AuthMethod = 10 // RFC4754
// AUTH_ECDSA_521                         AuthMethod = 11 // RFC4754
// TODO: RFC 7427 - Signature Authentication in IKEv2

// authenticates peer
func authenticate(msg *Message, initB []byte, idP *protocol.IdPayload, tkm *Tkm, idRemote Identity) bool {
	authP := msg.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	authenticator := authenticator(idRemote, tkm)
	switch authP.AuthMethod {
	case protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		pskId, ok := idRemote.(*PskIdentities)
		if !ok {
			log.Errorf("Ike Auth failed: PSK not configured for peer")
			return false
		}
		return authenticator.Verify(initB, idP, authP.Data, pskId)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE:
		certId, ok := idRemote.(*RsaCertIdentity)
		if !ok {
			log.Errorf("Ike Auth failed: RSA certificate not configured for peer")
			return false
		}
		certP := msg.Payloads.Get(protocol.PayloadTypeCERT)
		if certP == nil {
			log.Errorf("Ike Auth failed: certificate is required")
			return false
		}
		cert := certP.(*protocol.CertPayload)
		if cert.CertEncodingType != protocol.X_509_CERTIFICATE_SIGNATURE {
			log.Errorf("Ike Auth failed: cert encoding not supported: %v", cert.CertEncodingType)
			return false
		}
		// cert.data is DER-encoded X.509 certificate
		x509Cert, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			log.Errorf("Ike Auth failed: uanble to parse cert: %s", err)
			return false
		}
		certId.Certificate = x509Cert
		return authenticator.Verify(initB, idP, authP.Data, certId)
	}
	log.Errorf("Ike Auth failed: auth method not supported: %d", authP.AuthMethod)
	return false
}

// HandleIkeAuth callback from state machine
func (o *Session) HandleIkeAuth(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	// response
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	payloads := AuthIPayloads
	if o.tkm.isInitiator {
		payloads = AuthRPayloads
	}
	if err := m.EnsurePayloads(payloads); err != nil {
		// notification is recoverable
		for _, n := range m.Payloads.GetNotifications() {
			if _, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
				// if notification was an error,  pass it along
				s.Data = n.NotificationType
				return
			}
		}
		log.Error(err)
		s.Data = err
		return
	}
	var idP *protocol.IdPayload
	var initB []byte
	if o.tkm.isInitiator {
		initB = o.initRb
		idP = m.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	} else {
		initB = o.initIb
		idP = m.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	}
	// authenticate peer
	if !authenticate(m, initB, idP, o.tkm, o.idRemote) {
		log.Error(protocol.AUTHENTICATION_FAILED)
		// IkeErrorCode instead of NotificationType
		s.Data = protocol.ERR_AUTHENTICATION_FAILED
		return
	}
	log.Infof("IKE SA CREATED: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	s.Event = state.SUCCESS
	// move to STATE_MATURE state
	o.fsm.Event(state.StateEvent{Event: state.SUCCESS, Data: m})
	return
}
