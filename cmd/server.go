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

func read(p *ipv4.PacketConn) (b []byte, from net.Addr, to net.IP, err error) {
	b = make([]byte, 1500)
	n, cm, from, err := p.ReadFrom(b)
	if err == nil {
		b = b[:n]
		to = cm.Dst
	}
	return
}

func write(p *ipv4.PacketConn, reply []byte, from net.IP, to net.Addr) error {
	cm := ipv4.ControlMessage{
		Src: from,
	}
	if n, err := p.WriteTo(reply, &cm, to); err != nil {
		return err
	} else if n != len(reply) {
		return fmt.Errorf("short write: %v of %v", n, len(reply))
	}
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
	var localString string

	flag.StringVar(&localString, "local", "0.0.0.0:5000", "address to bind to")
	flag.Set("logtostderr", "true")
	flag.Parse()

	cxt, cancel := context.WithCancel(context.Background())

	ids := ike.PskIdentities{
		Primary: "ak@msgbox.io",
		Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
	}

	udp, err := net.ListenPacket("udp4", localString)
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	p := ipv4.NewPacketConn(udp)
	defer p.Close()
	log.Infof("socket listening: %s", udp.LocalAddr())

	cf := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	if err := p.SetControlMessage(cf, true); err != nil { // probe before test
		if nettest.ProtocolNotSupported(err) {
			log.Warningf("not supported on %s", runtime.GOOS)
		}
		log.Fatal(err)
	}

	sessions := make(map[uint64]*ike.Session)

	runSession := func(spi uint64, session *ike.Session, from net.IP, to net.Addr) {
		sessions[spi] = session
		for {
			select {
			case reply, ok := <-session.Replies():
				if !ok {
					break
				}
				if err = write(p, reply, from, to); err != nil {
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

	for {
		b, from, to, err := read(p)
		if err != nil {
			log.Fatal(err)
			return
		}
		msg, err := decode(b)
		if err != nil {
			log.Error(err)
			continue
		}
		// convert spi to uint64 for map lookup
		spi, _ := packets.ReadB64(msg.IkeHeader.SpiI, 0)
		session, found := sessions[spi]
		if !found {
			responder, err := ike.NewResponder(cxt, ids, ike.AddrToIp(from), to, msg)
			if err != nil {
				log.Error(err)
				continue
			}
			session = &responder.Session
			go runSession(spi, session, to, from)
		}
		session.HandleMessage(msg)
	}
	cancel(context.Canceled)

}
