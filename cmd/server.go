package main

import (
	"flag"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/ike/protocol"
	"msgbox.io/log"
	"msgbox.io/packets"
)

func runSession(session *ike.Session, spi uint64, sessions map[uint64]*ike.Session, conn net.Conn, remote net.Addr) {
	sessions[spi] = session
	for {
		select {
		case reply, ok := <-session.Replies():
			if !ok {
				break
			}
			// unconnected socker write
			if err := ike.WritePacket(reply, conn, remote, false); err != nil {
				log.Error(err)
			}
		case <-session.Done():
			delete(sessions, spi)
			log.Infof("Finished SA 0x%x", spi)
			return
		}
	}
}

func main() {
	var local string

	flag.StringVar(&local, "local", "0.0.0.0:5000", "address to bind to")
	flag.Set("logtostderr", "true")
	flag.Parse()

	cxt, cancel := context.WithCancel(context.Background())

	ids := ike.PskIdentities{
		Primary: "ak@msgbox.io",
		Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
	}

	localU, _ := net.ResolveUDPAddr("udp4", local)
	udp, err := net.ListenUDP("udp4", localU)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("socket listening: %s", localU)

	sessions := make(map[uint64]*ike.Session)
	for {
		b, remote, err := ike.ReadPacket(udp, nil, false)
		if err != nil {
			log.Fatal(err)
		}
		msg := &ike.Message{}
		if err := msg.DecodeHeader(b); err != nil {
			continue
		}
		if len(b) < int(msg.IkeHeader.MsgLength) {
			log.V(4).Info("")
			continue
		}
		// further decode
		if err = msg.DecodePayloads(b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
			// o.Notify(ERR_INVALID_SYNTAX)
			continue
		}
		// decrypt later
		msg.Data = b
		// convert spi to uint64 for map lookup
		spi, _ := packets.ReadB64(msg.IkeHeader.SpiI, 0)
		session, found := sessions[spi]
		if !found {
			remoteU := remote.(*net.UDPAddr)
			responder, err := ike.NewResponder(cxt, ids, remoteU, localU, msg)
			if err != nil {
				log.Error(err)
				continue
			}
			session = &responder.Session
			go runSession(session, spi, sessions, udp, remote)
		}
		session.HandleMessage(msg)
	}
	cancel(context.Canceled)
}
