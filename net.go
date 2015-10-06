package ike

import (
	"encoding/hex"
	"net"

	"msgbox.io/log"
)

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

func EncodeTx(msg *Message, tkm *Tkm, conn net.Conn, remote net.Addr, isConnected bool) (msgB []byte, err error) {
	if msgB, err = msg.Encode(tkm); err != nil {
		return
	} else {
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
		return msgB, nil
	}
}
