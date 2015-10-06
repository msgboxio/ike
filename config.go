package ike

import (
	"errors"
	"net"

	"msgbox.io/ike/protocol"
)

type ClientCfg struct {
	IkeTransforms, EspTransforms []*protocol.SaTransform

	ProposalIke, ProposalEsp *protocol.SaProposal

	TsI, TsR []*protocol.Selector

	IsTransportMode bool
}

func TunnelConfig() *ClientCfg {
	return &ClientCfg{
		IkeTransforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: protocol.ESP_AES_CBC_SHA1_96,
		ProposalIke: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.IKE,
			Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.ESP,
			Transforms: protocol.ESP_AES_CBC_SHA1_96,
		},
		TsI: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
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
		IkeTransforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: protocol.ESP_AES_CBC_SHA1_96,
		ProposalIke: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.IKE,
			Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.ESP,
			Transforms: protocol.ESP_AES_CBC_SHA1_96,
		},
		TsI: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: from,
			EndAddress:   from,
			// StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			// EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
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
	var ikeProp *protocol.SaProposal
	ikeSa := initI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	for _, prop := range ikeSa.Proposals {
		switch prop.ProtocolId {
		case protocol.IKE:
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
		IkeTransforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		EspTransforms: protocol.ESP_AES_CBC_SHA1_96,
		ProposalIke: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.IKE,
			Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
		},
		ProposalEsp: &protocol.SaProposal{
			IsLast:     true,
			Number:     2,
			ProtocolId: protocol.ESP,
			Transforms: protocol.ESP_AES_CBC_SHA1_96,
		},
		TsI: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*protocol.Selector{&protocol.Selector{
			Type:         protocol.TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
	}, nil
}
