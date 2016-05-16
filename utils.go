package ike

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

func MakeSpi() (ret protocol.Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	return spi.Bytes()
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

func newTkmFromInit(initI *Message, cfg *Config, ids Identities) (tkm *Tkm, err error) {
	keI := initI.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	// make sure dh tranform id is the one that was accepted
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if uint16(keI.DhTransformId) != tr {
		log.Warningf("Using different DH transform than the one configured %s vs %s",
			tr,
			keI.DhTransformId)
	}
	cs, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		return
	}
	tkm, err = NewTkmResponder(cs, keI.KeyData, noI.Nonce, ids) // TODO
	return
}
