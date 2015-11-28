package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/ike/ike_error"
	"msgbox.io/log"
)

func waitForSignal(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel(errors.New("received signal: " + sig.String()))
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

done:
	for {
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

		config := ike.NewClientConfig()
		config.AddSelector(
			&net.IPNet{IP: localU.IP.To4(), Mask: net.CIDRMask(32, 32)},
			&net.IPNet{IP: remoteU.IP.To4(), Mask: net.CIDRMask(32, 32)})
		if !isTunnelMode {
			config.IsTransportMode = true
		}
		cli := ike.NewInitiator(context.Background(), ids, udp, remoteU.IP, localU.IP, config)
		select {
		case <-cxt.Done():
			cli.Close()
			// wait until client is done
			<-cli.Done()
			fmt.Printf("shutdown client: %v\n", cli.Err())
			break done
		case <-cli.Done():
			fmt.Printf("client finished: %v\n", cli.Err())
			if cli.Err() == ike_error.PeerDeletedSa {
				continue
			}
			// if _, ok := cli.Err().(ike.IkeError); ok {
			// 	break done
			// }
			break done
		}
	}
}
