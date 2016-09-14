package ike

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/msgboxio/ike/protocol"
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
