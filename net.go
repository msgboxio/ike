package ike

import (
	"bytes"
	"net"

	"github.com/pkg/errors"
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

// copy of a useful function from ip.go
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

// IPNetToFirstLastAddress returns the first & last address derived from the IPNet notation
func IPNetToFirstLastAddress(n *net.IPNet) (first, last net.IP, err error) {
	ip, m := networkNumberAndMask(n)
	if ip == nil {
		err = errors.New("cannot extract bounds from address: " + n.String())
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
		return check4(ip.IP)
	case *net.UDPAddr:
		return check4(ip.IP)
	}
	return nil
}

func check4(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func AddrToIpPort(addr net.Addr) (net.IP, int) {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return check4(udp.IP), udp.Port
	} else if tcp, ok := addr.(*net.TCPAddr); ok {
		return check4(tcp.IP), tcp.Port
	}
	panic("enexpected addr " + addr.String())
}
