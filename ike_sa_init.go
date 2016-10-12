package ike

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

type CookieError struct {
	Cookie *protocol.NotifyPayload
}

func (e CookieError) Error() string {
	return "Rx Cookie"
}

var MissingCookieError = errors.New("Missing COOKIE")

var Version []byte
var Secret [64]byte

func init() {
	Version = []byte{0, 0}
	rand.Read(Secret[:])
}

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
	if o.initCookie != nil {
		init.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:       &protocol.PayloadHeader{},
			NotificationType:    protocol.COOKIE,
			NotificationMessage: o.initCookie,
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
	if o.rfc7427Signatures {
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

func notificationResponse(spi protocol.Spi, nt protocol.NotificationType, nBuf []byte) []byte {
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
	reply, err := msg.Encode(nil, false)
	if err != nil {
		panic(err)
	}
	return reply
}

func getCookie(initI *Message) []byte {
	// Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
	digest := sha1.New()
	no := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	digest.Write(no.Nonce.Bytes())
	digest.Write(initI.IkeHeader.SpiI)
	digest.Write(AddrToIp(initI.RemoteAddr))
	digest.Write(Secret[:])
	return append(Version, digest.Sum(nil)...)
}

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
	if cookie := m.Payloads.GetNotification(protocol.COOKIE); cookie != nil {
		if !bytes.Equal(cookie.NotificationMessage.([]byte), getCookie(m)) {
			return protocol.ERR_INVALID_KE_PAYLOAD
		}
	} else {
		// TODO - this is only temporary; use config to enable DDOS protection
		return MissingCookieError
	}

	if err := cfg.CheckFromInit(m); err != nil {
		return err
	}
	// TODO - check if config is usable
	// check if transforms are usable
	keI := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	// make sure dh tranform id is the one that was accepted
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != keI.DhTransformId {
		log.Warningf("Using different DH transform [%s] vs the one configured [%s]",
			keI.DhTransformId, dh)
		return protocol.ERR_INVALID_KE_PAYLOAD
	}
	return nil
}

func InitErrorNeedsReply(initI *Message, config *Config, err error) []byte {
	if err == protocol.ERR_INVALID_KE_PAYLOAD {
		buf := []byte{0, 0}
		packets.WriteB16(buf, 0, config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId)
		return notificationResponse(initI.IkeHeader.SpiI, protocol.INVALID_KE_PAYLOAD, buf)
	} else if err == MissingCookieError {
		return notificationResponse(initI.IkeHeader.SpiI, protocol.COOKIE, getCookie(initI))
	}
	return nil
}

func CheckInitResponseForSession(o *Session, m *Message) error {
	if m.IkeHeader.ExchangeType != protocol.IKE_SA_INIT ||
		!m.IkeHeader.Flags.IsResponse() ||
		m.IkeHeader.Flags.IsInitiator() ||
		m.IkeHeader.MsgId != 0 {
		return protocol.ERR_INVALID_SYNTAX
	}
	// make sure responder spi is not the same as initiator spi
	if bytes.Compare(m.IkeHeader.SpiR, m.IkeHeader.SpiI) == 0 {
		return protocol.ERR_INVALID_SYNTAX
	}
	if cookie := m.Payloads.GetNotification(protocol.COOKIE); cookie != nil {
		return CookieError{cookie}
	}
	// make sure responder spi is set
	// in case messages are being reflected - TODO
	if SpiToInt64(m.IkeHeader.SpiR) == 0 {
		return protocol.ERR_INVALID_SYNTAX
	}
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		return err
	}
	return nil
}

// SetInitiatorParameters sets session parameters from incoming IKE_SA_INIT response
func SetInitiatorParameters(o *Session, m *Message) {
	// for responder these were set by factory
	// responders nonce
	no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	o.tkm.Nr = no.Nonce
	// responders spi
	o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
}

func HandleInitForSession(o *Session, m *Message) error {
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
	log.V(1).Infof(o.Tag() + "IKE SA INITIALISED")
	// save Data
	if o.isInitiator {
		o.initRb = m.Data
	} else {
		o.initIb = m.Data
	}
	// process notifications
	var rfc7427Signatures = false
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.SIGNATURE_HASH_ALGORITHMS:
			log.V(2).Infof(o.Tag()+"Peer requested %s", protocol.AUTH_DIGITAL_SIGNATURE)
			rfc7427Signatures = true
		case protocol.NAT_DETECTION_DESTINATION_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, m.LocalAddr) {
				log.V(2).Infof("HOST nat detected: %s", m.LocalAddr)
			}
		case protocol.NAT_DETECTION_SOURCE_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, m.RemoteAddr) {
				log.V(2).Infof("PEER nat detected: %s", m.RemoteAddr)
			}
		}
	}
	o.SetHashAlgorithms(rfc7427Signatures)
	return nil
}

func checkNatHash(digest []byte, spiI, spiR protocol.Spi, addr net.Addr) bool {
	target := getNatHash(spiI, spiR, addr)
	// log.Infof("Their:\n%sOur:\n%s", hex.Dump(digest), hex.Dump(target))
	return bytes.Equal(digest, target)
}

func getNatHash(spiI, spiR protocol.Spi, addr net.Addr) []byte {
	ip, port := AddrToIpPort(addr)
	digest := sha1.New()
	digest.Write(spiI)
	digest.Write(spiR)
	digest.Write(ip)
	portb := []byte{0, 0}
	packets.WriteB16(portb, 0, uint16(port))
	digest.Write(portb)
	// log.Infof("\n%s%s%s%s", hex.Dump(spiI), hex.Dump(spiR), hex.Dump(ip), hex.Dump(portb))
	return digest.Sum(nil)
}
