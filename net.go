package ike

import (
	"bytes"
	"encoding/hex"
	"net"

	"msgbox.io/log"
)

func FirstLastAddressToIPNet(start, end net.IP) *net.IPNet {
	l := len(start)
	if l != len(end) {
		return nil
	}
	// shortcut
	if bytes.Equal(start, end) {
		return &net.IPNet{IP: start, Mask: net.CIDRMask(l*8, l*8)}
	}
	mask := make([]byte, l)
	// This will only work if there are no holes in addresses given
	for idx, _ := range start {
		mask[idx] = ^(end[idx] - start[idx])
	}
	return &net.IPNet{IP: start, Mask: mask}
}

func IPNetToFirstAddress(n *net.IPNet) net.IP {
	first := make([]byte, len(n.IP))
	for idx, _ := range n.IP {
		first[idx] = n.IP[idx] & n.Mask[idx]
	}
	return first
}

func IPNetToLastAddress(n *net.IPNet) net.IP {
	last := make([]byte, len(n.IP))
	for idx, _ := range n.IP {
		last[idx] = (n.IP[idx] & n.Mask[idx]) | ^n.Mask[idx]
	}
	return last
}

func ReadPacket(conn net.Conn, remote net.Addr, isConnected bool) (b []byte, from net.Addr, err error) {
	b = make([]byte, 1500)
	n := 0
	if isConnected {
		n, err = conn.Read(b)
		from = remote
	} else {
		udp := conn.(*net.UDPConn)
		n, from, err = udp.ReadFromUDP(b)
	}
	if err != nil {
		return nil, nil, err
	}
	b = b[:n]
	log.Infof("%d from %s", n, from)
	log.V(4).Info("\n" + hex.Dump(b))
	return b, from, nil
}

func WritePacket(msgB []byte, conn net.Conn, remote net.Addr, isConnected bool) (err error) {
	var n int
	if isConnected {
		n, err = conn.Write(msgB)
	} else {
		udp := conn.(*net.UDPConn)
		addr := remote.(*net.UDPAddr)
		n, err = udp.WriteToUDP(msgB, addr)
	}
	if err != nil {
		return
	} else {
		log.Infof("%d to %s", n, remote)
		log.V(4).Info("\n" + hex.Dump(msgB))
	}
	return nil
}
