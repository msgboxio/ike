package ike

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

// IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]
func InitFromSession(o *Session) *Message {
	nonce := o.tkm.Ni
	if !o.isInitiator {
		nonce = o.tkm.Nr
	}
	proposals := ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.IkeSpiI)
	flags := protocol.RESPONSE
	// nonce := tkm.Nr
	if o.isInitiator {
		flags = protocol.INITIATOR
		// nonce = tkm.Ni
	}
	init := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         o.IkeSpiI,
			SpiR:         o.IkeSpiR,
			NextPayload:  protocol.PayloadTypeSA,
			MajorVersion: protocol.IKEV2_MAJOR_VERSION,
			MinorVersion: protocol.IKEV2_MINOR_VERSION,
			ExchangeType: protocol.IKE_SA_INIT,
			Flags:        flags,
		},
		Payloads: protocol.MakePayloads(),
	}
	init.Payloads.Add(&protocol.SaPayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Proposals:     proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: o.tkm.suite.DhGroup.DhTransformId,
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

// InvalidKeMsg returns an encoded message with given dh transformID
func InvalidKeMsg(spi protocol.Spi, transformID uint16) []byte {
	buf := []byte{0, 0}
	packets.WriteB16(buf, 0, transformID)
	msg := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         spi,
			NextPayload:  protocol.PayloadTypeN,
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
		NotificationType:    protocol.NotificationType(protocol.INVALID_KE_PAYLOAD),
		NotificationMessage: buf,
	})
	reply, err := msg.Encode(nil, false)
	if err != nil {
		panic(err)
	}
	return reply
}

func HandleInitForSession(o *Session, m *Message) error {
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		return err
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		return err
	}
	// set Nr
	if o.isInitiator {
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		o.tkm.Nr = no.Nonce
		// set spiR
		o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	}
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof(o.Tag() + "IKE SA INITIALISED")
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
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, o.local) {
				log.V(2).Info("Encountered DEST nat")
			}
		case protocol.NAT_DETECTION_SOURCE_IP:
			if !checkNatHash(ns.NotificationMessage.([]byte), m.IkeHeader.SpiI, m.IkeHeader.SpiR, o.remote) {
				log.V(2).Info("Encountered SOURCE nat")
			}
		}
	}
	o.SetHashAlgorithms(rfc7427Signatures)
	return nil
}

func checkNatHash(digest []byte, spiI, spiR protocol.Spi, addr net.Addr) bool {
	return bytes.Equal(digest, getNatHash(spiI, spiR, addr))
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
	log.Infof("\n%s%s%s%s", hex.Dump(spiI), hex.Dump(spiR), hex.Dump(ip), hex.Dump(portb))
	return digest.Sum(nil)
}
