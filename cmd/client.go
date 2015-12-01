package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/ike/ike_error"
	"msgbox.io/ike/protocol"
	"msgbox.io/log"
)

func waitForSignal(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel(errors.New("received signal: " + sig.String()))
}

func runReader(o *ike.Initiator, conn net.Conn) {
done:
	for {
		select {
		case <-o.Done():
			break done
		default:
			b, _, err := ike.ReadPacket(conn, conn.RemoteAddr(), true)
			if err != nil {
				log.Error(err)
				o.Close(err)
				break done
			}
			// check if client closed the session
			if o.Err() != nil {
				break done
			}
			// if o.remote != nil && o.remote.String() != from.String() {
			// 	log.Errorf("from different address: %s", from)
			// 	continue
			// }
			msg := &ike.Message{}
			if err := msg.DecodeHeader(b); err != nil {
				o.Notify(protocol.ERR_INVALID_SYNTAX)
				continue
			}
			if len(b) < int(msg.IkeHeader.MsgLength) {
				log.V(protocol.LOG_CODEC).Info("")
				o.Notify(protocol.ERR_INVALID_SYNTAX)
				continue
			}
			if spi := msg.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
				log.Errorf("different initiator Spi %s", spi)
				o.Notify(protocol.ERR_INVALID_SYNTAX)
				continue
			}
			pld := b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength]
			if err = msg.DecodePayloads(pld, msg.IkeHeader.NextPayload); err != nil {
				o.Notify(protocol.ERR_INVALID_SYNTAX)
				continue
			}
			// decrypt later
			msg.Data = b
			o.HandleMessage(msg)
		}
	}
}

func main() {
	var remote string
	flag.StringVar(&remote, "remote", "127.0.0.1:5000", "address to connect to")
	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	flag.Set("logtostderr", "true")
	flag.Parse()

	remoteU, _ := net.ResolveUDPAddr("udp4", remote)

	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel)

	// use random local address
	udp, err := net.DialUDP("udp4", nil, remoteU)
	if err != nil {
		panic(err)
	}
	localU := udp.LocalAddr().(*net.UDPAddr)
	log.Infof("socket connected: %s<=>%s", localU, remoteU)

	ids := ike.PskIdentities{
		Primary: "ak@msgbox.io",
		Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
	}

	for {
		config := ike.NewClientConfig()
		config.AddSelector(
			&net.IPNet{IP: localU.IP.To4(), Mask: net.CIDRMask(32, 32)},
			&net.IPNet{IP: remoteU.IP.To4(), Mask: net.CIDRMask(32, 32)})
		if !isTunnelMode {
			config.IsTransportMode = true
		}
		cli := ike.NewInitiator(context.Background(), ids, remoteU, localU, config)
		go runReader(cli, udp)

	loop:
		for {
			select {
			case reply := <-cli.Replies():
				if err = ike.WritePacket(reply, udp, remoteU, true); err != nil {
					log.Error(err)
					break loop
				}
			case <-cli.Done():
				fmt.Printf("client finished: %v\n", cli.Err())
				// if _, ok := cli.Err().(ike.IkeError); ok {
				// 	break done
				// }
				break loop
			case <-cxt.Done():
				cli.Close(cxt.Err())
				// drain replies
				for reply := range cli.Replies() {
					if err = ike.WritePacket(reply, udp, remoteU, true); err != nil {
						log.Error(err)
					}
				}
				// wait until client is done
				<-cli.Done()
				fmt.Printf("shutdown client: %v\n", cli.Err())
				break loop
			}
		}
		if cli.Err() == ike_error.PeerDeletedSa {
			continue
		}
		break
	}
}
