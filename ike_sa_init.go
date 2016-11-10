package ike

import (
	"bytes"

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
func InitFromSession(o *Session) *Message {
	flags := protocol.RESPONSE
	nonce := o.tkm.Nr
	if o.isInitiator {
		flags = protocol.INITIATOR
		nonce = o.tkm.Ni
	}
	proposals := ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.IkeSpiI)
	init := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         o.IkeSpiI,
			SpiR:         o.IkeSpiR,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	if o.responderCookie != nil {
		init.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:       &protocol.PayloadHeader{},
			NotificationType:    protocol.COOKIE,
			NotificationMessage: o.responderCookie,
		})
	}
	init.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: o.tkm.suite.DhGroup.TransformId(),
		KeyData:       o.tkm.DhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         nonce,
	})
	// HashAlgorithmId has been set
	if o.cfg.AuthMethod == protocol.AUTH_DIGITAL_SIGNATURE {
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

func notificationResponse(spi protocol.Spi, nt protocol.NotificationType, nBuf []byte) *Message {
	msg := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         spi,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        protocol.RESPONSE,
			MsgId:        0,
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

// CheckInitRequest checks IKE_SA_INIT requests
func CheckInitRequest(cfg *Config, m *Message) error {
	if m.IkeHeader.ExchangeType != protocol.IKE_SA_INIT ||
		m.IkeHeader.Flags.IsResponse() ||
		!m.IkeHeader.Flags.IsInitiator() ||
		m.IkeHeader.MsgId != 0 {
		return protocol.ERR_INVALID_SYNTAX
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		return err
	}
	// did we get a COOKIE ?
	if cookie := m.Payloads.GetNotification(protocol.COOKIE); cookie != nil {
		// is COOKIE correct ?
		if !bytes.Equal(cookie.NotificationMessage.([]byte), getCookie(m)) {
			return errors.Wrap(MissingCookieError, "invalid cookie")
		}
	} else if cfg.ThrottleInitRequests {
		return errors.Wrap(MissingCookieError, "requesting cookie")
	}
	// check if transforms are usable
	keI := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	// make sure dh tranform id is the one that was configured
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != keI.DhTransformId {
		return errors.Wrapf(protocol.ERR_INVALID_KE_PAYLOAD,
			"Using different DH transform [%s] vs the one configured [%s]",
			keI.DhTransformId, dh)
	}
	// get SA payload
	ikeSa := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	// check ike proposal
	if err := cfg.CheckProposals(protocol.IKE, ikeSa.Proposals); err != nil {
		return err
	}
	return nil
}

func InitErrorNeedsReply(initI *Message, config *Config, err error) *Message {
	switch cause := errors.Cause(err); cause {
	case protocol.ERR_INVALID_KE_PAYLOAD:
		// ask PEER for correct DH type
		buf := []byte{0, 0}
		packets.WriteB16(buf, 0, config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId)
		return notificationResponse(initI.IkeHeader.SpiI, protocol.INVALID_KE_PAYLOAD, buf)
	case MissingCookieError:
		// ask peer to send cookie
		return notificationResponse(initI.IkeHeader.SpiI, protocol.COOKIE, getCookie(initI))
	}
	return nil
}

func CheckInitResponseForSession(o *Session, m *Message) error {
	if m.IkeHeader.ExchangeType != protocol.IKE_SA_INIT || // message must be init
		!m.IkeHeader.Flags.IsResponse() || // must be response
		m.IkeHeader.Flags.IsInitiator() || // must be a responder
		m.IkeHeader.MsgId != 0 { // id must be zero
		return protocol.ERR_INVALID_SYNTAX
	}
	// make sure responder spi is not the same as initiator spi
	if bytes.Equal(m.IkeHeader.SpiR, m.IkeHeader.SpiI) {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	// handle INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, or COOKIE
	for _, notif := range m.Payloads.GetNotifications() {
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
	if SpiToInt64(m.IkeHeader.SpiR) == 0 {
		return errors.WithStack(protocol.ERR_INVALID_SYNTAX)
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		return err
	}
	return nil
}

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
func HandleInitForSession(o *Session, m *Message) error {
	// process notifications
	var rfc7427Signatures = false
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.SIGNATURE_HASH_ALGORITHMS:
			o.Logger.Infof("Peer requested %s", protocol.AUTH_DIGITAL_SIGNATURE)
			rfc7427Signatures = true
		case protocol.NAT_DETECTION_DESTINATION_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, m.LocalAddr) {
				o.Logger.Infof("HOST nat detected: %s", m.LocalAddr)
			}
		case protocol.NAT_DETECTION_SOURCE_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, m.RemoteAddr) {
				o.Logger.Infof("PEER nat detected: %s", m.RemoteAddr)
			}
		}
	}
	if err := checkSignatureAlgo(o, rfc7427Signatures); err != nil {
		return err
	}

	if o.isInitiator {
		// peer responders nonce
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		o.tkm.Nr = no.Nonce
		// peer responders spi
		o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	}
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req

	// initialize dh shared with their public key
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
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
