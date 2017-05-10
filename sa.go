package ike

import (
	"math/big"

	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
)

// ni, nr, dhShared can either be from the original Tkm
// or from the rekeyed Tkm when Perfect Forward Secrecy is used
func addSaParams(tkm *Tkm,
	ni, nr, dhShared *big.Int,
	espSpiI, espSpiR []byte,
	cfg *Config,
	forInitiator bool) *platform.SaParams {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaKeys(ni, nr, dhShared)
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	return &platform.SaParams{
		PolicyParams:  policyParameters(cfg, forInitiator),
		EspEi:         espEi,
		EspAi:         espAi,
		EspEr:         espEr,
		EspAr:         espAr,
		SpiI:          int(SpiI),
		SpiR:          int(SpiR),
		EspTransforms: cfg.ProposalEsp,
	}
}

func removeSaParams(espSpiI, espSpiR []byte,
	cfg *Config,
	forInitiator bool) *platform.SaParams {
	// sa processing
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	return &platform.SaParams{
		PolicyParams: policyParameters(cfg, forInitiator),
		SpiI:         int(SpiI),
		SpiR:         int(SpiR),
	}
}

func policyParameters(cfg *Config, forInitiator bool) *protocol.PolicyParams {
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	return &protocol.PolicyParams{
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		IsTransportMode: cfg.IsTransportMode,
	}
}
