package ike

import (
	"io"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Conn interface {
	ReadPacket() (b []byte, remoteAddr, localAddr net.Addr, err error)
	WritePacket(reply []byte, remoteAddr net.Addr) error
	Inner() net.Conn
	Close() error
}

// check if types are implemented
var _ Conn = (*pconnV4)(nil)
var _ Conn = (*pconnV6)(nil)

type pconnV4 ipv4.PacketConn

func (c *pconnV4) Inner() net.Conn {
	return c.Conn
}

func (c *pconnV4) Close() error {
	return c.Conn.Close()
}

type pconnV6 ipv6.PacketConn

func (c *pconnV6) Inner() net.Conn {
	return c.Conn
}

func (c *pconnV6) Close() error {
	return c.Conn.Close()
}

// ErrorUDPOnly is returned if the given address is other than UDP
var ErrorUDPOnly = errors.New("only udp is supported for now")

// checkV4onX will check if
// addresses like "localhost:500" can listen as v4 addresses
// normally, if we bind on dual stack address
// on mac, receiving from v4 addresses does not give remote address
func checkV4onX(address string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return false
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		return true
	}
	return false
}

func Listen(network, address string, logger log.Logger) (Conn, error) {
	// use v4 if at all possilbe on mac
	if checkV4onX(address) {
		return listenUDP4(address, logger)
	}
	switch network {
	case "udp4":
		return listenUDP4(address, logger)
	case "udp6", "udp":
		return listenUDP6(address, logger)
	}
	return nil, ErrorUDPOnly
}

func listenUDP4(localString string, logger log.Logger) (p4 *pconnV4, err error) {
	udp, err := net.ListenPacket("udp4", localString)
	if err != nil {
		return nil, errors.Wrap(err, "listening V4")
	}
	p := ipv4.NewPacketConn(udp)
	// the interface could be set to any(0.0.0.0)
	// we need the exact address the packet came on
	cf := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil {
		if protocolNotSupported(err) {
			level.Warn(logger).Log("msg", "udp source address detection not supported", "on", runtime.GOOS)
		} else {
			p.Close()
			return nil, err
		}
	}
	logger.Log("listening V4", udp.LocalAddr())
	return (*pconnV4)(p), nil
}

func listenUDP6(localString string, logger log.Logger) (p6 *pconnV6, err error) {
	udp, err := net.ListenPacket("udp", localString)
	if err != nil {
		return nil, errors.Wrap(err, "listening")
	}
	p := ipv6.NewPacketConn(udp)
	// the interface could be set to any(0.0.0.0)
	// we need the exact address the packet came on
	cf := ipv6.FlagSrc | ipv6.FlagDst | ipv6.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil {
		if protocolNotSupported(err) {
			level.Warn(logger).Log("msg", "udp source address detection not supported", "on", runtime.GOOS)
		} else {
			p.Close()
			return nil, err
		}
	}
	logger.Log("listening", udp.LocalAddr())
	return (*pconnV6)(p), nil
}

func (p *pconnV4) ReadPacket() (b []byte, remoteAddr, localAddr net.Addr, err error) {
	b = make([]byte, 3000) // section 2
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		port := p.Inner().LocalAddr().(*net.UDPAddr).Port
		localAddr = &net.UDPAddr{
			IP:   cm.Dst,
			Port: port,
		}
	}
	return
}

func (p *pconnV6) ReadPacket() (b []byte, remoteAddr, localAddr net.Addr, err error) {
	b = make([]byte, 3000) // section 2
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		if cm != nil { // nil on mac
			port := p.Inner().LocalAddr().(*net.UDPAddr).Port
			localAddr = &net.UDPAddr{
				IP:   cm.Dst,
				Port: port,
			}
		}
	}
	return
}

func (p *pconnV6) WritePacket(reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return io.ErrShortWrite
	}
	return nil
}

func (p *pconnV4) WritePacket(reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return io.ErrShortWrite
	}
	return nil
}

// ReadMessage reads an IKE message from connection
// Connection errors are returned, protocol errors are simply logged
// TODO - defrag logic seems wrong; revisit
func ReadMessage(conn Conn, log log.Logger) (*Message, error) {
	var buf []byte
	for {
		b, remoteAddr, localAddr, err := conn.ReadPacket()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		log.Log("read", len(b), "from", remoteAddr)
		if buf != nil {
			b = append(buf, b...)
			buf = nil
		}
		msg, err := DecodeMessage(b, log)
		if err == io.ErrShortBuffer {
			buf = b
			continue
		}
		if err != nil {
			level.Error(log).Log(err)
			continue
		}
		msg.LocalAddr = localAddr
		msg.RemoteAddr = remoteAddr
		return msg, nil
	}
}

func WriteMessage(conn Conn, msg *Message, tkm *Tkm, forInitiator bool, log log.Logger) (err error) {
	data, err := msg.Encode(tkm, forInitiator, log)
	if err != nil {
		return err
	}
	return WriteData(conn, data, msg.RemoteAddr, log)
}

func WriteData(conn Conn, data []byte, remote net.Addr, log log.Logger) (err error) {
	err = conn.WritePacket(data, remote)
	log.Log("write", len(data), "to", remote, "error", err)
	return
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
