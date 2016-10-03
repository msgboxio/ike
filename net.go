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
	"golang.org/x/net/ipv6"

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
	panic("enexpected addr " + addr.String())
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

type pconnV4 struct {
	*ipv4.PacketConn
}

// LocalAddr is essential in order to fulfill the net.Conn contract
func (c *pconnV4) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

type pconnV6 struct {
	*ipv6.PacketConn
}

// LocalAddr is essential in order to fulfill the net.Conn contract
func (c *pconnV6) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

var ErrorUdpOnly = errors.New("only udp is supported for now")

func Listen(network, address string) (net.Conn, error) {
	switch network {
	case "udp4":
		return listenUDP4(address)
	case "udp6":
		return listenUDP6(address)
	}
	return nil, ErrorUdpOnly
}

func listenUDP4(localString string) (p4 *pconnV4, err error) {
	udp, err := net.ListenPacket("udp4", localString)
	if err != nil {
		return
	}
	p := ipv4.NewPacketConn(udp)
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
	return &pconnV4{p}, nil
}

func listenUDP6(localString string) (p6 *pconnV6, err error) {
	udp, err := net.ListenPacket("udp6", localString)
	if err != nil {
		return
	}
	p := ipv6.NewPacketConn(udp)
	// the interface could be set to any(0.0.0.0)
	// we need the exact address the packet came on
	cf := ipv6.FlagSrc | ipv6.FlagDst | ipv6.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil {
		if protocolNotSupported(err) {
			log.Warningf("udp source address detection not supported on %s", runtime.GOOS)
		} else {
			p.Close()
			return nil, err
		}
	}
	return &pconnV6{p}, nil
}

func ReadPacket(p net.Conn) (b []byte, remoteAddr net.Addr, localIP net.IP, err error) {
	if p4Conn, ok := p.(*pconnV4); ok {
		return readPacketV4(p4Conn)
	} else if p6Conn, ok := p.(*pconnV6); ok {
		return readPacketV6(p6Conn)
	}
	return nil, nil, nil, errors.New("only udp v4 is supported for now")
}

func readPacketV4(p *pconnV4) (b []byte, remoteAddr net.Addr, localIP net.IP, err error) {
	b = make([]byte, 3000) // section 2
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		localIP = cm.Dst
	}
	log.V(1).Infof("%d from %v", n, remoteAddr)
	return
}

func readPacketV6(p *pconnV6) (b []byte, remoteAddr net.Addr, localIP net.IP, err error) {
	b = make([]byte, 3000) // section 2
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		localIP = cm.Dst
	}
	log.V(1).Infof("%d from %v", n, remoteAddr)
	return
}

func WritePacket(p net.Conn, reply []byte, remoteAddr net.Addr) error {
	if p4Conn, ok := p.(*pconnV4); ok {
		return writePacketV4(p4Conn, reply, remoteAddr)
	} else if p6Conn, ok := p.(*pconnV6); ok {
		return writePacketV6(p6Conn, reply, remoteAddr)
	}
	return ErrorUdpOnly
}

func writePacketV4(p *pconnV4, reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return io.ErrShortWrite
	}
	log.V(1).Infof("%d to %v", n, remoteAddr)
	return nil
}

func writePacketV6(p *pconnV6, reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return io.ErrShortWrite
	}
	log.V(1).Infof("%d to %v", n, remoteAddr)
	return nil
}

func ReadMessage(conn net.Conn) (*Message, error) {
	var buf []byte
	for {
		b, remoteAddr, localIP, err := ReadPacket(conn)
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
		port := conn.LocalAddr().(*net.UDPAddr).Port
		msg.LocalAddr = &net.UDPAddr{
			IP:   localIP,
			Port: port,
		}
		msg.RemoteAddr = remoteAddr
		return msg, nil
	}
}

func InnerConn(p net.Conn) net.Conn {
	if p4Conn, ok := p.(*pconnV4); ok {
		return p4Conn.Conn
	} else if p6Conn, ok := p.(*pconnV6); ok {
		return p6Conn.Conn
	}
	return nil
}
