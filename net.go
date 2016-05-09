package ike

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"

	"github.com/msgboxio/log"
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

// copy of the incredbly useful function from ip.go
func networkNumberAndMask(n *net.IPNet) (ip net.IP, m net.IPMask) {
	if ip = n.IP.To4(); ip == nil {
		ip = n.IP
		if len(ip) != net.IPv6len {
			return nil, nil
		}
	}
	m = n.Mask
	switch len(m) {
	case net.IPv4len:
		if len(ip) != net.IPv4len {
			return nil, nil
		}
	case net.IPv6len:
		if len(ip) == net.IPv4len {
			m = m[12:]
		}
	default:
		return nil, nil
	}
	return
}

// Returns the first & last derived from the ipnet notation
func IPNetToFirstLastAddress(n *net.IPNet) (first, last net.IP, err error) {
	ip, m := networkNumberAndMask(n)
	if ip == nil {
		err = errors.New("cannot extract bounds from address")
		return
	}
	last = make([]byte, len(ip))
	first = make([]byte, len(ip))
	for idx, val := range ip {
		first[idx] = val & m[idx]
		last[idx] = (val & m[idx]) | ^m[idx]
	}
	return
}

func AddrToIp(addr net.Addr) net.IP {
	switch ip := addr.(type) {
	case *net.TCPAddr:
		return ip.IP
	case *net.UDPAddr:
		return ip.IP
	}
	return nil
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
