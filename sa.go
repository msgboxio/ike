package ike

import (
	"net"

	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/packets"
)

func addSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	cfg *Config,
	local, remote net.Addr,
	forInitiator bool) *platform.SaParams {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaCreate(ikeSpiI, ikeSpiR)
	SpiI, _ := packets.ReadB32(espSpiI, 0)
	SpiR, _ := packets.ReadB32(espSpiR, 0)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	localIP := AddrToIp(local)
	remoteIP := AddrToIp(remote)
	sa := &platform.SaParams{
		// src, dst for initiator
		Ini:             localIP,
		Res:             remoteIP,
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
	if !forInitiator {
		sa.Ini = remoteIP
		sa.Res = localIP
		sa.IsResponder = true
	}
	return sa
}

func removeSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	cfg *Config,
	local, remote net.Addr,
	forInitiator bool) *platform.SaParams {
	// sa processing
	SpiI, _ := packets.ReadB32(espSpiI, 0)
	SpiR, _ := packets.ReadB32(espSpiR, 0)
	tsI := cfg.TsI[0]
	tsR := cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	localIP := AddrToIp(local)
	remoteIP := AddrToIp(remote)
	sa := &platform.SaParams{
		Ini:             localIP,
		Res:             remoteIP,
		IniPort:         0,
		ResPort:         0,
		IniNet:          iNet,
		ResNet:          rNet,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: cfg.IsTransportMode,
	}
	if !forInitiator {
		sa.Ini = remoteIP
		sa.Res = localIP
		sa.IsResponder = true
	}
	return sa
}
