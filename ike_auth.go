package ike

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

type authParams struct {
	isResponse      bool
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

func makeAuth(params *authParams, initB []byte) (*Message, error) {
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
			return nil, errors.New("missing Certificate Identity")
		}
		if certId.Certificate == nil {
			return nil, errors.New("missing Identity")
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
		return nil, err
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
	return auth, nil
}

// SendAuth callback from state machine
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
		}, initB)
}

func parseSa(m *Message) (*authParams, error) {
	params := &authParams{}
	if m.IkeHeader.Flags&protocol.RESPONSE != 0 {
		params.isResponse = true
	}
	if m.IkeHeader.Flags&protocol.INITIATOR != 0 {
		params.isInitiator = true
	}
	if err := m.EnsurePayloads(SaPayloads); err == nil {
		espSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		if espSa.Proposals == nil {
			return nil, errors.New("proposals are missing")
		}
		params.proposals = espSa.Proposals
		spi, err := spiFromProposal(params.proposals, protocol.ESP)
		if err != nil {
			return nil, err
		}
		if params.isInitiator {
			params.spiI = spi
		} else {
			params.spiR = spi
		}
		// get selectors
		tsI := m.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
		tsR := m.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
		if len(tsI) == 0 || len(tsR) == 0 {
			return nil, errors.New("acceptable traffic selectors are missing")
		}
		params.tsI = tsI
		params.tsR = tsR
	}
	// notifications
	wantsTransportMode := false
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.AUTH_LIFETIME:
			params.lifetime = ns.NotificationMessage.(time.Duration)
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	params.isTransportMode = wantsTransportMode
	return params, nil
}

// HandleAuthForSession currently supports signature authenticaiton using
// AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE (psk)
// AUTH_RSA_DIGITAL_SIGNATURE with certificates
// RFC 7427 - Signature Authentication in IKEv2
// tkm.Auth always uses the hash negotiated with prf
// TODO: implement raw AUTH_RSA_DIGITAL_SIGNATURE & AUTH_DSS_DIGITAL_SIGNATURE
// TODO: implement ECDSA from RFC4754
func HandleAuthForSession(o *Session, m *Message) (err error) {
	if m.IkeHeader.ExchangeType != protocol.IKE_AUTH {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: incorrect type")
	}
	payloads := AuthIPayloads
	if o.isInitiator {
		payloads = AuthRPayloads
	}
	if err := m.EnsurePayloads(payloads); err != nil {
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
		o.Logger.Info("Ike Auth: SHARED_KEY of ", string(idP.Data))
		return o.authRemote.Verify(initB, idP, authP.Data)
	case protocol.AUTH_RSA_DIGITAL_SIGNATURE, protocol.AUTH_DIGITAL_SIGNATURE:
		chain, err := m.Payloads.GetCertchain()
		if err != nil {
			return err
		}
		cert := FormatCert(chain[0])
		o.Logger.Infof("Ike Auth: PEER CERT: %+v", cert)
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
		return certAuth.Verify(initB, idP, authP.Data)
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
	if o.Logger.Level == logrus.DebugLevel {
		o.Logger.Debugf("params: \n%s; err %+v", spew.Sdump(params), err)
	}
	if err != nil {
		return err
	}
	if err = o.cfg.CheckProposals(protocol.ESP, params.proposals); err != nil {
		return err
	}
	// TODO - check selector
	o.Logger.Infof("Configured selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)
	o.Logger.Infof("Offered selectors: [INI]%s<=>%s[RES]", params.tsI, params.tsR)
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
		o.Logger.Infof("Lifetime: %s; reauth in %s", params.lifetime, reauth)
		// TODO - start alarm for reauth
		// time.AfterFunc(reauth, func() {
		// 	o.Logger.Info("Lifetime Expired")
		// 	o.PostEvent(&state.StateEvent{Event: state.REKEY_START})
		// })
	}
	// transport mode
	if params.isTransportMode && o.cfg.IsTransportMode {
		o.Logger.Info("Using Transport Mode")
	} else {
		if params.isTransportMode {
			o.Logger.Info("Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			err = errors.New("Peer Rejected Transport Mode Config")
			return err
		}
	}
	return nil
}
