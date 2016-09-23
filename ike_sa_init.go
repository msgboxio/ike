package ike

import (
	"math/big"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

type initParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi
	proposals   []*protocol.SaProposal

	nonce *big.Int
	protocol.DhTransformId
	dhPublic *big.Int

	rfc7427Signatures bool
}

// IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]
func makeInit(p initParams) *Message {
	flags := protocol.RESPONSE
	// nonce := tkm.Nr
	if p.isInitiator {
		flags = protocol.INITIATOR
		// nonce = tkm.Ni
	}
	init := &Message{
		IkeHeader: &protocol.IkeHeader{
			SpiI:         p.spiI,
			SpiR:         p.spiR,
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
		Proposals:     p.proposals,
	})
	init.Payloads.Add(&protocol.KePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		DhTransformId: p.DhTransformId,
		KeyData:       p.dhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         p.nonce,
	})
	// HashAlgorithmId has been set
	if p.rfc7427Signatures {
		buf := [8]byte{}
		packets.WriteB16(buf[:], 0, uint16(protocol.HASH_SHA1))
		packets.WriteB16(buf[:], 2, uint16(protocol.HASH_SHA2_256))
		packets.WriteB16(buf[:], 4, uint16(protocol.HASH_SHA2_384))
		packets.WriteB16(buf[:], 6, uint16(protocol.HASH_SHA2_512))
		init.Payloads.Add(&protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			NotificationType: protocol.SIGNATURE_HASH_ALGORITHMS,
			Data:             buf[:],
		})
	}
	return init
}

func InitFromSession(o *Session) *Message {
	nonce := o.tkm.Ni
	if !o.tkm.isInitiator {
		nonce = o.tkm.Nr
	}
	return makeInit(initParams{
		isInitiator:       o.tkm.isInitiator,
		spiI:              o.IkeSpiI,
		spiR:              o.IkeSpiR,
		proposals:         ProposalFromTransform(protocol.IKE, o.cfg.ProposalIke, o.IkeSpiI),
		nonce:             nonce,
		DhTransformId:     o.tkm.suite.DhGroup.DhTransformId,
		dhPublic:          o.tkm.DhPublic,
		rfc7427Signatures: o.rfc7427Signatures,
	})
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
	if o.tkm.isInitiator {
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		o.tkm.Nr = no.Nonce
		// set spiR
		o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	}
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof(o.Tag() + "IKE SA INITIALISED")
	// save Data
	if o.tkm.isInitiator {
		o.initRb = m.Data
	} else {
		o.initIb = m.Data
	}
	// process notifications
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.SIGNATURE_HASH_ALGORITHMS:
			log.V(2).Infof(o.Tag()+"received hash algos: %+v", ns.NotificationMessage.([]protocol.HashAlgorithmId))
			o.SetHashAlgorithms()
		}
	}
	return nil
}
