package main

import (
	"flag"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/net/internal/nettest"
	"golang.org/x/net/ipv4"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/ike/protocol"
	"msgbox.io/log"
	"msgbox.io/packets"
)

func listen(localString string) (p *ipv4.PacketConn, err error) {
	udp, err := net.ListenPacket("udp4", localString)
	if err != nil {
		return
	}
	p = ipv4.NewPacketConn(udp)

	cf := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil { // probe before test
		if nettest.ProtocolNotSupported(err) {
			log.Warningf("not supported on %s", runtime.GOOS)
		} else {
			p.Close()
			return nil, err
		}
	}
	return
}

func read(p *ipv4.PacketConn) (b []byte, remoteAddr net.Addr, localIP net.IP, err error) {
	b = make([]byte, 1500)
	n, cm, remoteAddr, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		localIP = cm.Dst
	}
	log.V(1).Infof("%d from %v", n, remoteAddr)
	return
}

func write(p *ipv4.PacketConn, reply []byte, remoteAddr net.Addr) error {
	n, err := p.WriteTo(reply, nil, remoteAddr)
	if err != nil {
		return err
	} else if n != len(reply) {
		return fmt.Errorf("short write: %v of %v", n, len(reply))
	}
	log.V(1).Infof("%d to %v", n, remoteAddr)
	return nil
}

func decode(b []byte) (msg *ike.Message, err error) {
	msg = &ike.Message{}
	if err = msg.DecodeHeader(b); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = fmt.Errorf("short packet: %v vs %v", len(b), msg.IkeHeader.MsgLength)
		return
	}
	// further decode
	if err = msg.DecodePayloads(b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
		// o.Notify(ERR_INVALID_SYNTAX)
		return
	}
	// decrypt later
	msg.Data = b
	return
}

func main() {
	var localString, remoteString string
	flag.StringVar(&localString, "local", "0.0.0.0:5000", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	flag.Set("logtostderr", "true")
	flag.Parse()

	cxt, cancel := context.WithCancel(context.Background())

	ids := ike.PskIdentities{
		Primary: "ak@msgbox.io",
		Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
	}

	p, err := listen(localString)
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()
	log.Infof("socket listening: %s", p.Conn.LocalAddr())

	sessions := make(map[uint64]*ike.Session)

	runSession := func(spi uint64, session *ike.Session, to net.Addr) {
		sessions[spi] = session
		for {
			select {
			case reply, ok := <-session.Replies():
				if !ok {
					break
				}
				if err = write(p, reply, to); err != nil {
					session.Close(err)
					break
				}
			case <-session.Done():
				delete(sessions, spi)
				log.Infof("Finished SA 0x%x", spi)
				return
			}
		}
	}

	if remoteString != "" {
		remoteAddr, _ := net.ResolveUDPAddr("udp4", remoteString)
		config := ike.NewClientConfig()
		if !isTunnelMode {
			config.IsTransportMode = true
		}
		initiator := ike.NewInitiator(context.Background(), ids, ike.AddrToIp(remoteAddr).To4(), config)
		spi, _ := packets.ReadB64(initiator.IkeSpiI, 0)
		go runSession(spi, &initiator.Session, remoteAddr)
	}

	for {
		b, remoteAddr, localIP, err := read(p)
		if err != nil {
			log.Fatal(err)
			return
		}
		msg, err := decode(b)
		if err != nil {
			log.Error(err)
			continue
		}
		msg.LocalIp = localIP
		msg.RemoteIp = ike.AddrToIp(remoteAddr)
		// convert spi to uint64 for map lookup
		spi, _ := packets.ReadB64(msg.IkeHeader.SpiI, 0)
		session, found := sessions[spi]
		if !found {
			responder, err := ike.NewResponder(cxt, ids, msg)
			if err != nil {
				log.Error(err)
				continue
			}
			session = &responder.Session
			go runSession(spi, session, remoteAddr)
		}
		session.HandleMessage(msg)
	}
	cancel(context.Canceled)
}
