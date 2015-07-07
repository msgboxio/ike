package main

import (
	"flag"
	"fmt"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/log"
)

func main() {
	var remote string
	// 0.0.0.0 is for listening
	flag.StringVar(&remote, "remote", "127.0.0.1:5000", "address to connect to")
	flag.Set("logtostderr", "true")
	flag.Parse()

	remoteU, _ := net.ResolveUDPAddr("udp4", remote)

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

	transportMode := ike.TransportCfg(localU.IP, remoteU.IP)
	cli := ike.NewInitiator(context.Background(), ids, udp, remoteU.IP, localU.IP, transportMode)
	<-cli.Done()
	fmt.Printf("client finished: %v\n", cli.Err())
}
