package ike

import (
	"bytes"
	"math/big"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
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
	dhTransformId protocol.DhTransformId
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
			MsgId:        0, // ALWAYS
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
		DhTransformId: params.dhTransformId,
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

// InitFromSession creates IKE_SA_INIT messages
func InitFromSession(o *Session) *Message {
	nonce := o.tkm.Nr
	if o.isInitiator {
		nonce = o.tkm.Ni
	}
	return makeInit(&initParams{
		isInitiator:       o.isInitiator,
		spiI:              o.IkeSpiI,
		spiR:              o.IkeSpiR,
		proposals:         ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.IkeSpiI),
		cookie:            o.responderCookie,
		dhTransformId:     o.tkm.suite.DhGroup.TransformId(),
		dhPublic:          o.tkm.DhPublic,
		nonce:             nonce,
		rfc7427Signatures: o.cfg.AuthMethod == protocol.AUTH_DIGITAL_SIGNATURE,
	})
}

func notificationResponse(spi protocol.Spi, nt protocol.NotificationType, nBuf []byte) *Message {
	msg := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         spi,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        protocol.RESPONSE,
			MsgId:        0, // ALWAYS
		},
		Payloads: protocol.MakePayloads(),
	}
	msg.Payloads.Add(&protocol.NotifyPayload{
		PayloadHeader:       &protocol.PayloadHeader{},
		ProtocolId:          protocol.IKE,
		NotificationType:    nt,
		NotificationMessage: nBuf,
	})
	return msg
}

func parseInit(m *Message) (*initParams, error) {
	params := &initParams{}
	if m.IkeHeader.ExchangeType != protocol.IKE_SA_INIT {
		return nil, errors.Wrap(protocol.ERR_INVALID_SYNTAX, "IKE_SA_INIT: incorrect type")
	}
	//
	if m.IkeHeader.MsgId != 0 {
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
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		return nil, err
	}
	params.spiI = m.IkeHeader.SpiI
	params.spiR = m.IkeHeader.SpiR
	params.ns = m.Payloads.GetNotifications()
	// did we get a COOKIE ?
	if cookie := m.Payloads.GetNotification(protocol.COOKIE); cookie != nil {
		params.cookie = cookie.NotificationMessage.([]byte)
	}
	// check if transforms are usable
	keI := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	params.dhTransformId = keI.DhTransformId
	params.dhPublic = keI.KeyData
	// get SA payload
	ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	params.proposals = ikeSa.Proposals
	// nonce payload
	nonce := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	params.nonce = nonce.Nonce
	return params, nil
}

// CheckInitRequest checks IKE_SA_INIT requests
func CheckInitRequest(cfg *Config, init *initParams, remote net.Addr) error {
	if !init.isInitiator {
		return protocol.ERR_INVALID_SYNTAX
	}
	// did we get a COOKIE ?
	if cookie := init.cookie; cookie != nil {
		// is COOKIE correct ?
		if !bytes.Equal(cookie, getCookie(init.nonce, init.spiI, remote)) {
			return errors.Wrap(MissingCookieError, "invalid cookie")
		}
	} else if cfg.ThrottleInitRequests {
		return errors.Wrap(MissingCookieError, "requesting cookie")
	}
	// check if transforms are usable
	// make sure dh tranform id is the one that was configured
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != init.dhTransformId {
		return errors.Wrapf(protocol.ERR_INVALID_KE_PAYLOAD,
			"Using different DH transform [%s] vs the one configured [%s]",
			init.dhTransformId, dh)
	}
	// check ike proposal
	if err := cfg.CheckProposals(protocol.IKE, init.proposals); err != nil {
		return err
	}
	return nil
}

func InitErrorNeedsReply(init *initParams, config *Config, remote net.Addr, err error) *Message {
	switch cause := errors.Cause(err); cause {
	case protocol.ERR_INVALID_KE_PAYLOAD:
		// ask PEER for correct DH type
		buf := []byte{0, 0}
		packets.WriteB16(buf, 0, config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId)
		return notificationResponse(init.spiI, protocol.INVALID_KE_PAYLOAD, buf)
	case MissingCookieError:
		// ask peer to send cookie
		return notificationResponse(init.spiI, protocol.COOKIE, getCookie(init.nonce, init.spiI, remote))
	}
	return nil
}

func CheckInitResponseForSession(o *Session, init *initParams) error {
	if init.isInitiator { // id must be zero
		return protocol.ERR_INVALID_SYNTAX
	}
	// make sure responder spi is not the same as initiator spi
	if bytes.Equal(init.spiR, init.spiI) {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	// handle INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	for _, notif := range init.ns {
		switch notif.NotificationType {
		case protocol.COOKIE:
			return CookieError{notif}
		case protocol.INVALID_KE_PAYLOAD:
			return protocol.ERR_INVALID_KE_PAYLOAD
		case protocol.NO_PROPOSAL_CHOSEN:
			return protocol.ERR_NO_PROPOSAL_CHOSEN
		}
	}
	// make sure responder spi is set
	// in case messages are being reflected - TODO
	if SpiToInt64(init.spiR) == 0 {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	return nil
}

// return error secure signatures are configured, but not proposed by peer
func checkSignatureAlgo(o *Session, isEnabled bool) error {
	if !isEnabled {
		o.Logger.Warningf("Not using secure signatures")
		if o.cfg.AuthMethod == protocol.AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE {
			return errors.New("Peer is not using secure signatures")
		}
	}
	return nil
}

// HandleInitForSession expects the message given to it to be well formatted
func HandleInitForSession(o *Session, init *initParams, m *Message) error {
	// process notifications
	// check NAT-T payload to determine if there is a NAT between the two peers
	var rfc7427Signatures = false
	for _, ns := range init.ns {
		switch ns.NotificationType {
		case protocol.SIGNATURE_HASH_ALGORITHMS:
			o.Logger.Infof("Peer requested %s", protocol.AUTH_DIGITAL_SIGNATURE)
			rfc7427Signatures = true
		case protocol.NAT_DETECTION_DESTINATION_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), init.spiI, init.spiR, m.LocalAddr) {
				o.Logger.Infof("HOST nat detected: %s", m.LocalAddr)
			}
		case protocol.NAT_DETECTION_SOURCE_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), init.spiI, init.spiR, m.RemoteAddr) {
				o.Logger.Infof("PEER nat detected: %s", m.RemoteAddr)
			}
		}
	}
	// returns error if secure signatures are configured, but not proposed by peer
	if err := checkSignatureAlgo(o, rfc7427Signatures); err != nil {
		return err
	}
	// get nonce & spi from responder's response
	if o.isInitiator {
		// peer responders nonce
		o.tkm.Nr = init.nonce
		// peer responders spi
		o.IkeSpiR = append([]byte{}, init.spiR...)
	}
	// TODO
	// If there is NAT , then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	//
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// initialize dh shared with their public key
	if err := o.tkm.DhGenerateKey(init.dhPublic); err != nil {
		return err
	}
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	o.Logger.Info("IKE SA INITIALISED", o)
	// save Data
	if o.isInitiator {
		o.initRb = m.Data
	} else {
		o.initIb = m.Data
	}
	return nil
}
