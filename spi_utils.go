package ike

import (
	"crypto/rand"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func SpiToInt64(spi protocol.Spi) uint64 {
	ret, _ := packets.ReadB64(spi, 0)
	return ret
}

func SpiToInt32(spi protocol.Spi) uint32 {
	ret, _ := packets.ReadB32(spi, 0)
	return ret
}

func MakeSpi() (ret protocol.Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	return spi.Bytes()
}

func getPeerSpi(m *Message, pid protocol.ProtocolID) (peerSpi protocol.Spi, err error) {
	// first exchange contains peer spi // TODO - MAJOR hack
	if m.IkeHeader.MsgID == 0 && (pid == protocol.IKE) {
		peerSpi = m.IkeHeader.SpiI
		return
	}
	if peerSpi == nil {
		err = errors.New("Unknown Peer SPI")
		return
	}
	return
}

func spiFromProposal(props []*protocol.SaProposal, pid protocol.ProtocolID) (protocol.Spi, error) {
	for _, p := range props {
		if !p.IsSpiSizeCorrect(len(p.Spi)) {
			return nil, errors.New("Bad SPI size ")
		}
		if p.ProtocolID == pid {
			return p.Spi, nil
		}
	}
	return nil, errors.New("Missing SPI")
}
