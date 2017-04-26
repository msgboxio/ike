package ike

import (
	"math/big"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var (
	initPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeKE,
		protocol.PayloadTypeNonce,
	}

	authIPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDi,
		protocol.PayloadTypeAUTH,
	}
	authRPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDr,
		protocol.PayloadTypeAUTH,
	}
	saPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}

	rekeyIkeSaPaylods = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeKE,
		protocol.PayloadTypeNonce,
	}

	rekeyChildSaPaylods = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeNonce,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
)

// IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]
type initParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi

	nonce         *big.Int
	proposals     []*protocol.SaProposal
	dhTransformID protocol.DhTransformId
	dhPublic      *big.Int

	ns                []*protocol.NotifyPayload
	cookie            []byte
	rfc7427Signatures bool
}

func makeInit(params *initParams) *Message {
	// response & initiator are mutually exclusive
	flags := protocol.RESPONSE
	if params.isInitiator {
		flags = protocol.INITIATOR
	}
	init := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         params.spiI,
			SpiR:         params.spiR,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        flags,
			MsgID:        0, // ALWAYS
		},
		Payloads: protocol.MakePayloads(),
	}
	if params.cookie != nil {
		init.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:       &protocol.PayloadHeader{},
			NotificationType:    protocol.COOKIE,
			NotificationMessage: params.cookie,
		})
	}
	init.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     params.proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: params.dhTransformID,
		KeyData:       params.dhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         params.nonce,
	})
	// HashAlgorithmId has been set
	if params.rfc7427Signatures {
		init.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.SIGNATURE_HASH_ALGORITHMS,
			NotificationMessage: []protocol.HashAlgorithmId{
				protocol.HASH_SHA1,
				protocol.HASH_SHA2_256,
				protocol.HASH_SHA2_384,
				protocol.HASH_SHA2_512,
			},
		})
	}
	// init.Payloads.Add(&protocol.NotifyPayload{
	// PayloadHeader:       &protocol.PayloadHeader{},
	// NotificationType:    protocol.NAT_DETECTION_DESTINATION_IP,
	// NotificationMessage: getNatHash(o.IkeSpiI, o.IkeSpiR, o.remote),
	// })
	// init.Payloads.Add(&protocol.NotifyPayload{
	// PayloadHeader:       &protocol.PayloadHeader{},
	// NotificationType:    protocol.NAT_DETECTION_SOURCE_IP,
	// NotificationMessage: getNatHash(o.IkeSpiI, o.IkeSpiR, o.local),
	// })
	return init
}

func parseInit(m *Message) (*initParams, error) {
	params := &initParams{}
	if m.IkeHeader.ExchangeType != protocol.IKE_SA_INIT {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: incorrect type")
	}
	//
	if m.IkeHeader.MsgID != 0 {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: invalid Message Id")
	}
	if m.IkeHeader.Flags.IsInitiator() {
		if m.IkeHeader.Flags.IsResponse() {
			return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: invalid flag")
		}
		params.isInitiator = true
	} else if !m.IkeHeader.Flags.IsResponse() {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: invalid flag")
	}
	params.spiI = m.IkeHeader.SpiI
	params.spiR = m.IkeHeader.SpiR
	params.ns = m.Payloads.GetNotifications()
	// did we get a COOKIE ?
	if cookie := m.Payloads.GetNotification(protocol.COOKIE); cookie != nil {
		params.cookie = cookie.NotificationMessage.([]byte)
	}
	// if we got a COOKIE request, then there are no more payloads
	if err := m.EnsurePayloads(initPayloads); err != nil {
		return params, err
	}
	// check if transforms are usable
	keI := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	params.dhTransformID = keI.DhTransformId
	params.dhPublic = keI.KeyData
	// get SA payload
	ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	params.proposals = ikeSa.Proposals
	// nonce payload
	nonce := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	params.nonce = nonce.Nonce
	return params, nil
}

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
// signed1 : init[i/r]B | N[r/i]

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

func makeAuth(params *authParams, initB []byte, logger log.Logger) (*Message, error) {
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
	signature, err := params.authenticator.Sign(initB, iDp, logger)
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

func checkAuth(m *Message, forInitiator bool) error {
	if m.IkeHeader.ExchangeType != protocol.IKE_AUTH {
		return errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_AUTH: incorrect type")
	}
	payloads := authIPayloads
	if forInitiator {
		payloads = authRPayloads
	}
	if err := m.EnsurePayloads(payloads); err != nil {
		return err
	}
	return nil
}

func parseSa(m *Message) (*authParams, error) {
	params := &authParams{}
	if m.IkeHeader.Flags&protocol.RESPONSE != 0 {
		params.isResponse = true
	}
	if m.IkeHeader.Flags&protocol.INITIATOR != 0 {
		params.isInitiator = true
	}
	if err := m.EnsurePayloads(saPayloads); err == nil {
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

// CREATE_CHILD_SA
// b<-a
//  HDR(SPIi=xxx, SPIy=yyy, CREATE_CHILD_SA, Flags: none, Message ID=m),
//  SK {SA, Ni, KEi} - ike sa
//  SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr} - for rekey child sa
//  SK {SA, Ni, [KEi,] TSi, TSr} - for new child sa, different selector perhaps
// a<-b
//  HDR(SPIi=xxx, SPIr=yyy, CREATE_CHILD_SA, Flags: Initiator | Response, Message ID=m),
//  SK {N(NO_ADDITIONAL_SAS} - reject
//  SK {SA, Nr, KEr} - ike sa
//  SK {SA, Nr, [KEr,] TSi, TSr} - child sa
type childSaParams struct {
	isResponse       bool
	isInitiator      bool
	isTransportMode  bool
	ikeSpiI, ikeSpiR protocol.Spi
	proposals        []*protocol.SaProposal
	tsI, tsR         []*protocol.Selector
	lifetime         time.Duration
	targetEspSpi     protocol.Spi // esp sa that is being replaced
	nonce            *big.Int
	dhTransformId    protocol.DhTransformId
	dhPublic         *big.Int
}

func makeChildSa(params *childSaParams) *Message {
	flags := protocol.IkeFlags(0)
	if params.isResponse {
		flags = protocol.RESPONSE
	}
	if params.isInitiator {
		flags |= protocol.INITIATOR
	}
	child := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         params.ikeSpiI,
			SpiR:         params.ikeSpiR,
			NextPayload:  protocol.PayloadTypeSK,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.CREATE_CHILD_SA,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	// presence of traffic selectors means that CHILD SA is being rekeyed
	if params.tsI != nil && params.tsR != nil && params.isInitiator {
		child.Payloads.Add(&protocol.NotifyPayload{
			ProtocolId:       protocol.ESP,
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.REKEY_SA,
			Spi:              params.targetEspSpi, // target esp
		})
	}
	child.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     params.proposals,
	})
	child.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         params.nonce,
	})
	if params.dhPublic != nil { // optional
		child.Payloads.Add(&protocol.KePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			DhTransformId: params.dhTransformId,
			KeyData:       params.dhPublic,
		})
	}
	if params.tsI != nil && params.tsR != nil {
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSi,
			Selectors:                  params.tsI,
		})
		child.Payloads.Add(&protocol.TrafficSelectorPayload{
			PayloadHeader:              &protocol.PayloadHeader{},
			TrafficSelectorPayloadType: protocol.PayloadTypeTSr,
			Selectors:                  params.tsR,
		})
	}
	if params.isTransportMode {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.USE_TRANSPORT_MODE,
		})
	}
	if !params.isInitiator && params.lifetime != 0 {
		child.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader: &protocol.PayloadHeader{},
			// ProtocolId:       IKE,
			NotificationType:    protocol.AUTH_LIFETIME,
			NotificationMessage: params.lifetime,
		})
	}
	return child
}

func parseChildSa(m *Message) (*childSaParams, error) {
	if m.IkeHeader.ExchangeType != protocol.CREATE_CHILD_SA {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "CREATE_CHILD_SA: incorrect type")
	}
	params := &childSaParams{}
	if m.IkeHeader.Flags&protocol.RESPONSE != 0 {
		params.isResponse = true
	}
	if m.IkeHeader.Flags&protocol.INITIATOR != 0 {
		params.isInitiator = true
	}
	rekeySA := m.Payloads.GetNotification(protocol.REKEY_SA)
	if rekeySA != nil {
		// received CREATE_CHILD_SA request
		// make sure protocol id is correct
		if rekeySA.ProtocolId != protocol.ESP {
			return nil, errors.New("REKEY child SA: Wrong protocol")
		}
		params.targetEspSpi = rekeySA.Spi
	}
	if err := m.EnsurePayloads(rekeyChildSaPaylods); err == nil {
		// rekeying IPSEC SA
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		tsI := m.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
		tsR := m.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
		if len(tsI) == 0 || len(tsR) == 0 {
			return nil,
				errors.New("REKEY child SA: acceptable traffic selectors are missing")
		}
		params.tsI = tsI
		params.tsR = tsR
		// check for optional KE payload
		if kep := m.Payloads.Get(protocol.PayloadTypeKE); kep != nil {
			keR := kep.(*protocol.KePayload)
			params.dhPublic = keR.KeyData
			params.dhTransformId = keR.DhTransformId
		}
	} else if err := m.EnsurePayloads(rekeyIkeSaPaylods); err == nil {
		// rekeying IKE SA
		// get sa & nonce
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		params.nonce = no.Nonce
		ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
		params.proposals = ikeSa.Proposals
		keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
		params.dhPublic = keR.KeyData
		params.dhTransformId = keR.DhTransformId
	} else {
		return nil, errors.New("REKEY packet is invalid")
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
