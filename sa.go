package ike

import (
	"math/big"

	"github.com/msgboxio/ike/platform"
)

// ni, nr, dhShared can either be from the original Tkm
// or from the rekeyed Tkm when Perfect Forward Secrecy is used
func addSaParams(tkm *Tkm,
	ni, nr, dhShared *big.Int,
	espSpiI, espSpiR []byte,
	cfg *Config) *platform.SaParams {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaKeys(ni, nr, dhShared)
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	return &platform.SaParams{
		PolicyParams:  cfg.Policy(),
		EspEi:         espEi,
		EspAi:         espAi,
		EspEr:         espEr,
		EspAr:         espAr,
		SpiI:          int(SpiI),
		SpiR:          int(SpiR),
		EspTransforms: cfg.ProposalEsp,
	}
}

func removeSaParams(espSpiI, espSpiR []byte, cfg *Config) *platform.SaParams {
	// sa processing
	SpiI := SpiToInt32(espSpiI)
	SpiR := SpiToInt32(espSpiR)
	return &platform.SaParams{
		PolicyParams: cfg.Policy(),
		SpiI:         int(SpiI),
		SpiR:         int(SpiR),
	}
}
