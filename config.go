package ike

import (
	"errors"
	"net"

	"msgbox.io/ike/protocol"
)

type ClientCfg struct {
	ProposalIke, ProposalEsp *protocol.SaProposal

	TsI, TsR []*protocol.Selector

	IsTransportMode bool
}

func TunnelConfig() *ClientCfg {
	return &ClientCfg{
		ProposalIke: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.IKE,
			//Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
			Transforms: protocol.IKE_AES_GCM_16_DH_1024,
		},
		ProposalEsp: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.ESP,
			//Transforms: protocol.ESP_AES_CBC_SHA1_96,
			Transforms: protocol.ESP_AES_GCM_16,
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
		ProposalIke: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.IKE,
			// Transforms: protocol.IKE_AES_CBC_SHA1_96_DH_1024,
			Transforms: protocol.IKE_AES_GCM_16_DH_1024,
		},
		ProposalEsp: &protocol.SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolId: protocol.ESP,
			// Transforms: protocol.ESP_AES_CBC_SHA1_96,
			Transforms: protocol.ESP_AES_GCM_16,
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
		IsTransportMode: true,
	}
}

func NewClientConfigFromInit(initI *Message) (*ClientCfg, error) {
	// get proposals
	var ikeProp *protocol.SaProposal
	ikeSa := initI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	// select first ones
	for _, prop := range ikeSa.Proposals {
		switch prop.ProtocolId {
		case protocol.IKE:
			if ikeProp == nil {
				ikeProp = prop
			}
		}
	}
	// TODO - check proposals, make sure they are acceptable
	if ikeProp == nil {
		return nil, errors.New("acceptable IKE proposals are missing")
	}
	return &ClientCfg{
		ProposalIke: ikeProp,
	}, nil
}

func AddClientConfigFromAuth(authI *Message, cfg *ClientCfg) error {
	var espProp *protocol.SaProposal
	espSa := authI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	// select first ones
	for _, prop := range espSa.Proposals {
		switch prop.ProtocolId {
		case protocol.ESP:
			if espProp == nil {
				espProp = prop
			}
		}
	}
	// TODO - check proposals, make sure they are acceptable
	if espProp == nil {
		return errors.New("acceptable ESP proposals are missing")
	}

	// get selectors
	tsI := authI.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
	tsR := authI.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
	if len(tsI) == 0 || len(tsR) == 0 {
		return errors.New("acceptable traffic selectors are missing")
	}

	cfg.ProposalEsp = espProp
	cfg.TsI = tsI
	cfg.TsR = tsR
	return nil
}
