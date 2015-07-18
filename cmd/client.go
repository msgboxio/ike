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
	// 0.0.0.0 is for listening
	flag.StringVar(&remote, "remote", "127.0.0.1:5000", "address to connect to")
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

		transportMode := ike.TransportCfg(localU.IP.To4(), remoteU.IP.To4())
		cli := ike.NewInitiator(context.Background(), ids, udp, remoteU.IP, localU.IP, transportMode)
		select {
		case <-cxt.Done():
			cli.Close()
			// wait it colint is doen
			<-cli.Done()
			fmt.Printf("client finished: %v\n", cli.Err())
			break done
		case <-cli.Done():
			fmt.Printf("client finished: %v\n", cli.Err())
			if _, ok := cli.Err().(ike.IkeError); ok {
				break done
			}
		}
	}
}
