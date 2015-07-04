package ike

type ClientCfg struct {
	IkeTransforms, EspTransforms []*SaTransform

	IkeSpiI, IkeSpiR Spi

	EspSpiI, EspSpiR []byte

	ProposalIke, ProposalEsp *SaProposal

	TsI, TsR []*Selector
}
