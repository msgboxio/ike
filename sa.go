package ike

import (
	"errors"
	"net"
	"time"

	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
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

// CheckSaForSession callback from state machine
func checkSaForSession(o *Session, msg *Message) (s state.StateEvent) {
	// get peer spi
	espSpi, err := getPeerSpi(msg, protocol.ESP)
	if err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	if o.isInitiator {
		o.EspSpiR = append([]byte{}, espSpi...)
	} else {
		o.EspSpiI = append([]byte{}, espSpi...)
	}
	// check transport mode, and other info payloads
	wantsTransportMode := false
	for _, ns := range msg.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.AUTH_LIFETIME:
			lft := ns.NotificationMessage.(time.Duration)
			reauth := lft - 2*time.Second
			if lft <= 2*time.Second {
				reauth = 0
			}
			log.Infof(o.Tag()+"Lifetime: %s; reauth in %s", lft, reauth)
			time.AfterFunc(reauth, func() {
				o.PostEvent(state.StateEvent{Event: state.REKEY_START})
			})
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	if wantsTransportMode && o.cfg.IsTransportMode {
		log.Info(o.Tag() + "Using Transport Mode")
	} else {
		if wantsTransportMode {
			log.Info(o.Tag() + "Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			err := errors.New("Peer Rejected Transport Mode Config")
			log.Error(o.Tag() + err.Error())
			s.Data = err
		}
	}
	// load additional configs
	if err := o.cfg.CheckromAuth(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - check IPSEC selectors & config
	s.Event = state.SUCCESS
	return
}
