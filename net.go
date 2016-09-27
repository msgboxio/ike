package ike

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/net/ipv4"

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

func AddrToIpPort(addr net.Addr) (net.IP, int) {
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.IP, udp.Port
	} else if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP, tcp.Port
	}
	panic("enexpected addr")
}

// copied from golang.org/x/net/internal/nettest
func protocolNotSupported(err error) bool {
	switch err := err.(type) {
	case syscall.Errno:
		switch err {
		case syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT:
			return true
		}
	case *os.SyscallError:
		switch err := err.Err.(type) {
		case syscall.Errno:
			switch err {
			case syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT:
				return true
			}
		}
	}
	return false
}

func Listen(localString string) (p *ipv4.PacketConn, err error) {
	udp, err := net.ListenPacket("udp4", localString)
	if err != nil {
		return
	}
	p = ipv4.NewPacketConn(udp)
	// the interface could be set to any(0.0.0.0)
	// we need the exact address the packet came on
	cf := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil {
		if protocolNotSupported(err) {
			log.Warningf("udp source address detection not supported on %s", runtime.GOOS)
		} else {
			p.Close()
			return nil, err
		}
	}
	return
}

func ReadPacket(p *ipv4.PacketConn) (b []byte, remoteAddr net.Addr, localIP net.IP, err error) {
	b = make([]byte, 3000) // section 2
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		localIP = cm.Dst
	}
	log.V(1).Infof("%d from %v", n, remoteAddr)
	return
}

func WritePacket(p *ipv4.PacketConn, reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return io.ErrShortWrite
	}
	log.V(1).Infof("%d to %v", n, remoteAddr)
	return nil
}

func ReadMessage(pconn *ipv4.PacketConn) (*Message, error) {
	var buf []byte
	for {
		b, remoteAddr, localIP, err := ReadPacket(pconn)
		if err != nil {
			return nil, err
		}
		if buf != nil {
			b = append(buf, b...)
			buf = nil
		}
		msg, err := DecodeMessage(b)
		if err == io.ErrShortBuffer {
			buf = b
			continue
		}
		if err != nil {
			log.Error(err)
			continue
		}
		port := pconn.Conn.LocalAddr().(*net.UDPAddr).Port
		msg.LocalAddr = &net.UDPAddr{
			IP:   localIP,
			Port: port,
		}
		msg.RemoteAddr = remoteAddr
		return msg, nil
	}
}
