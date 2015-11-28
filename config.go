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

func NewClientConfig() *ClientCfg {
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
	}
}

func (cfg *ClientCfg) AddSelector(from, to *net.IPNet) {
	cfg.TsI = []*protocol.Selector{&protocol.Selector{
		Type:         protocol.TS_IPV4_ADDR_RANGE,
		IpProtocolId: 0,
		StartPort:    0,
		Endport:      65535,
		StartAddress: IPNetToFirstAddress(from).To4(),
		EndAddress:   IPNetToLastAddress(from).To4(),
	}}
	cfg.TsR = []*protocol.Selector{&protocol.Selector{
		Type:         protocol.TS_IPV4_ADDR_RANGE,
		IpProtocolId: 0,
		StartPort:    0,
		Endport:      65535,
		StartAddress: IPNetToFirstAddress(to).To4(),
		EndAddress:   IPNetToLastAddress(to).To4(),
	}}
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
	if ikeProp == nil {
		return nil, errors.New("acceptable IKE proposals are missing")
	}
	return &ClientCfg{
		ProposalIke: ikeProp,
	}, nil
}

func (cfg *ClientCfg) AddFromAuth(authI *Message) error {
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
	if espProp == nil {
		return errors.New("acceptable ESP proposals are missing")
	}
	// get selectors
	tsI := authI.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload).Selectors
	tsR := authI.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload).Selectors
	if len(tsI) == 0 || len(tsR) == 0 {
		return errors.New("acceptable traffic selectors are missing")
	}
	// set & return
	cfg.ProposalEsp = espProp
	cfg.TsI = tsI
	cfg.TsR = tsR
	return nil
}
