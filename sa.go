package ike

import (
	"net"

	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

func addSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	cfg *Config,
	local, remote net.IP) (err error) {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaCreate(ikeSpiI, ikeSpiR)
	SpiI, _ := packets.ReadB32(espSpiI, 0)
	SpiR, _ := packets.ReadB32(espSpiR, 0)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	// print config
	sa := &platform.SaParams{
		// src, dst for initiator
		Ini:             local,
		Res:             remote,
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
	}
	if !tkm.isInitiator {
		sa.Ini = remote
		sa.Res = local
		sa.IsResponder = true
	}
	log.Infof("Installing Child SA: %#x<=>%#x; [%s]%s<=>%s[%s]",
		espSpiI, espSpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res)
	if err = platform.InstallChildSa(sa); err != nil {
		return err
	}
	log.Info("Installed Child SA")
	return
}

func removeSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	cfg *Config,
	local, remote net.IP) (err error) {
	// sa processing
	SpiI, _ := packets.ReadB32(espSpiI, 0)
	SpiR, _ := packets.ReadB32(espSpiR, 0)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	sa := &platform.SaParams{
		Ini:             local,
		Res:             remote,
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: cfg.IsTransportMode,
	}
	if !tkm.isInitiator {
		sa.Ini = remote
		sa.Res = local
		sa.IsResponder = true
	}
	if err = platform.RemoveChildSa(sa); err != nil {
		log.Error("Error removing child SA:", err)
		return err
	}
	log.Info("Removed child SA")
	return
}
