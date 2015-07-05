package ike

import "net"

type ClientCfg struct {
	IkeTransforms, EspTransforms []*SaTransform

	IkeSpiI, IkeSpiR Spi

	EspSpiI, EspSpiR []byte

	ProposalIke, ProposalEsp *SaProposal

	TsI, TsR []*Selector
}

func TransportCfg(from, to net.IP) *ClientCfg {
	ikeSpiI := MakeSpi()
	espSpi := MakeSpi()
	return &ClientCfg{
		IkeSpiI:       ikeSpiI,
		EspSpiI:       espSpi[:4],
		IkeTransforms: IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: ESP_AES_CBC_SHA1_96,
		ProposalIke: &SaProposal{
			Number:     1,
			ProtocolId: IKE,
			Spi:        []byte{}, // zero for ike sa init
			Transforms: IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &SaProposal{
			IsLast:     true,
			Number:     2,
			ProtocolId: ESP,
			Spi:        espSpi[:4],
			Transforms: ESP_AES_CBC_SHA1_96,
		},
		TsI: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
	}
}
