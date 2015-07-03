package ike

type ClientCfg struct {
	ikeTransforms, espTransforms []*SaTransform

	ikeSpiI, ikeSpiR Spi
	EspSpi           []byte

	proposalIke, proposalEsp *SaProposal

	TsI, TsR []*Selector
}
