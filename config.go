package ike

import (
	"errors"
	"net"
)

type ClientCfg struct {
	IkeTransforms, EspTransforms []*SaTransform

	ProposalIke, ProposalEsp *SaProposal

	TsI, TsR []*Selector

	IsTransportMode bool
}

func TunnelConfig() *ClientCfg {
	return &ClientCfg{
		IkeTransforms: IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: ESP_AES_CBC_SHA1_96,
		ProposalIke: &SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: IKE,
			Transforms: IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: ESP,
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

func TransportCfg(from, to net.IP) *ClientCfg {
	return &ClientCfg{
		IkeTransforms: IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: ESP_AES_CBC_SHA1_96,
		ProposalIke: &SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: IKE,
			Transforms: IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: ESP,
			Transforms: ESP_AES_CBC_SHA1_96,
		},
		TsI: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: from,
			EndAddress:   from,
			// StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			// EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: to,
			EndAddress:   to,
			// StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			// EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
	}
}

func NewClientConfigFromInit(initI *Message) (*ClientCfg, error) {
	// get proposals
	var ikeProp *SaProposal
	ikeSa := initI.Payloads.Get(PayloadTypeSA).(*SaPayload)
	for _, prop := range ikeSa.Proposals {
		switch prop.ProtocolId {
		case IKE:
			ikeProp = prop
		}
	}
	if ikeProp == nil {
		return nil, errors.New("acceptable IKE proposals are missing")
	}

	// get selectors
	// tsI := initI.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload).Selectors
	// tsR := initI.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload).Selectors
	// if len(tsI) == 0 || len(tsR) == 0 {
	// 	return nil, errors.New("acceptable selectors are missing")
	// }
	return &ClientCfg{
		IkeTransforms: IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: ESP_AES_CBC_SHA1_96,
		ProposalIke: &SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: IKE,
			Transforms: IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &SaProposal{
			IsLast:     true,
			Number:     2,
			ProtocolId: ESP,
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
	}, nil
}
