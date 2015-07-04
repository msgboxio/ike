package main

import (
	"flag"
	"fmt"
	"net"

	"msgbox.io/context"
	"msgbox.io/ike"
	"msgbox.io/log"
)

func NewClientCfg() *ike.ClientCfg {
	ikeSpiI := ike.MakeSpi()
	espSpi := ike.MakeSpi()
	return &ike.ClientCfg{
		IkeSpiI:       ikeSpiI,
		EspSpiI:       espSpi[:4],
		IkeTransforms: ike.IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: ike.ESP_AES_CBC_SHA1_96,
		ProposalIke: &ike.SaProposal{
			Number:     1,
			ProtocolId: ike.IKE,
			Spi:        []byte{}, // zero for ike sa init
			Transforms: ike.IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &ike.SaProposal{
			IsLast:     true,
			Number:     2,
			ProtocolId: ike.ESP,
			Spi:        espSpi[:4],
			Transforms: ike.ESP_AES_CBC_SHA1_96,
		},
		TsI: []*ike.Selector{&ike.Selector{
			Type:         ike.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*ike.Selector{&ike.Selector{
			Type:         ike.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
	}
}

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

	cli := ike.NewInitiator(context.Background(), udp, remoteU.IP, localU.IP, NewClientCfg())
	<-cli.Done()
	fmt.Printf("client finished: %v", cli.Err())
}
