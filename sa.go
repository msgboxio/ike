package ike

import (
	"math/big"

	"github.com/msgboxio/ike/platform"
)

func addSaParams(tkm *Tkm,
	ni, nr, dhShared *big.Int,
	espSpiI, espSpiR []byte,
	cfg *Config,
	forInitiator bool) *platform.SaParams {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaCreate(ni, nr, dhShared)
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	sa := &platform.SaParams{
		// src, dst for initiator
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		EspEi:           espEi,
		EspAi:           espAi,
		EspEr:           espEr,
		EspAr:           espAr,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: cfg.IsTransportMode,
		EspTransforms:   cfg.ProposalEsp,
	}
	if forInitiator {
		sa.IsInitiator = true
	}
	return sa
}

func removeSaParams(espSpiI, espSpiR []byte,
	cfg *Config,
	forInitiator bool) *platform.SaParams {
	// sa processing
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	sa := &platform.SaParams{
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: cfg.IsTransportMode,
	}
	if forInitiator {
		sa.IsInitiator = true
	}
	return sa
}
