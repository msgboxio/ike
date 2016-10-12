package ike

import (
	"bytes"
	"crypto/sha1"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/packets"
)

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
