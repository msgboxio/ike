package ike

import (
	"math/big"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

type initParams struct {
	isInitiator bool
	spiI, spiR  protocol.Spi
	proposals   []*protocol.SaProposal

	nonce         *big.Int
	dhTransformId protocol.DhTransformId
	dhPublic      *big.Int
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
		DhTransformId: p.dhTransformId,
		KeyData:       p.dhPublic,
	})
	init.Payloads.Add(&protocol.NoncePayload{
		PayloadHeader: &protocol.PayloadHeader{},
		Nonce:         p.nonce,
	})
	return init
}

func InitFromSession(tkm *Tkm, ikeSpiI, ikeSpiR []byte, cfg *Config) *Message {
	nonce := tkm.Ni
	if !tkm.isInitiator {
		nonce = tkm.Nr
	}
	return makeInit(initParams{
		isInitiator:   tkm.isInitiator,
		spiI:          ikeSpiI,
		spiR:          ikeSpiR,
		proposals:     ProposalFromTransform(protocol.IKE, cfg.ProposalIke, ikeSpiI),
		nonce:         nonce,
		dhTransformId: tkm.suite.DhGroup.DhTransformId,
		dhPublic:      tkm.DhPublic,
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
	return nil
}
