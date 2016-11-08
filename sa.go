package ike

import (
	"time"

	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/pkg/errors"
)

func addSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
	cfg *Config,
	forInitiator bool) *platform.SaParams {
	// sa processing
	espEi, espAi, espEr, espAr := tkm.IpsecSaCreate(ikeSpiI, ikeSpiR)
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

func removeSa(tkm *Tkm,
	ikeSpiI, ikeSpiR []byte,
	espSpiI, espSpiR []byte,
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

// CheckSaForSession callback from state machine
func checkSaForSession(o *Session, msg *Message) (s *state.StateEvent) {
	// get peer spi
	espSpi, err := getPeerSpi(msg, protocol.ESP)
	if err != nil {
		o.Logger.Error(err)
		s.Error = err
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
			o.Logger.Infof("Lifetime: %s; reauth in %s", lft, reauth)
			time.AfterFunc(reauth, func() {
				o.Logger.Info("Lifetime Expired")
				o.PostEvent(&state.StateEvent{Event: state.REKEY_START})
			})
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	if wantsTransportMode && o.cfg.IsTransportMode {
		o.Logger.Info("Using Transport Mode")
	} else {
		if wantsTransportMode {
			o.Logger.Info("Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			err := errors.New("Peer Rejected Transport Mode Config")
			o.Logger.Error(err.Error())
			s.Error = err
		}
	}
	// load additional configs
	if err := o.cfg.CheckfromAuth(msg, o.Logger); err != nil {
		o.Logger.Error(err)
		s.Error = err
		return
	}
	return
}
