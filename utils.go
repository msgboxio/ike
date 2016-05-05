package ike

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func MakeSpi() (ret protocol.Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	return spi.Bytes()
}

func getTransforms(pr []*protocol.SaProposal, proto protocol.ProtocolId) []*protocol.SaTransform {
	for _, p := range pr {
		if p.ProtocolId == proto {
			return p.Transforms
		}
	}
	return nil
}

func getPeerSpi(m *Message, pid protocol.ProtocolId) (peerSpi protocol.Spi, err error) {
	// first exchange contains peer spi // TODO - MAJOR hack
	if m.IkeHeader.MsgId == 0 && (pid == protocol.IKE) {
		peerSpi = m.IkeHeader.SpiI
		return
	}
	props := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload).Proposals
	for _, p := range props {
		if !p.IsSpiSizeCorrect(len(p.Spi)) {
			err = fmt.Errorf("weird spi size :%+v", *p)
			return
		}
		if p.ProtocolId == pid {
			peerSpi = p.Spi
		}
	}
	if peerSpi == nil {
		err = errors.New("Unknown Peer SPI")
		return
	}
	return
}

func newTkmFromInit(initI *Message, ids Identities) (tkm *Tkm, err error) {
	keI := initI.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	ikeSa := initI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	cs, err := crypto.NewCipherSuite(getTransforms(ikeSa.Proposals, protocol.IKE))
	if err != nil {
		return
	}
	// make sure dh tranform id is the one that was accepted
	if keI.DhTransformId != cs.DhGroup.DhTransformId {
		err = protocol.ERR_INVALID_KE_PAYLOAD
		return
	}
	tkm, err = NewTkmResponder(cs, keI.KeyData, noI.Nonce, ids) // TODO
	return
}
