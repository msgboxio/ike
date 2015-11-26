package ike

import (
	"errors"
	"net"
	"time"

	"msgbox.io/context"
	"msgbox.io/ike/platform"
	"msgbox.io/ike/protocol"
	"msgbox.io/ike/state"
	"msgbox.io/log"
	"msgbox.io/packets"
)

type stateEvents int

const (
	installChildSa stateEvents = iota + 1
	removeChildSa
)

type Session struct {
	context.Context
	cancel context.CancelFunc

	tkm *Tkm
	cfg *ClientCfg

	conn          net.Conn
	remote, local net.IP

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	messages chan *Message

	fsm *state.Fsm

	msgId uint32
}

func run(o *Session) {
done:
	for {
		select {
		case <-o.Done():
			break done
		case msg, ok := <-o.messages:
			if !ok {
				break done
			}
			evt := state.StateEvent{Data: msg}
			// make sure they are responses - TODO
			switch msg.IkeHeader.ExchangeType {
			case protocol.IKE_SA_INIT:
				evt.Event = state.MSG_INIT
				o.fsm.Event(evt)
			case protocol.IKE_AUTH:
				evt.Event = state.MSG_AUTH
				o.fsm.Event(evt)
			case protocol.CREATE_CHILD_SA:
				evt.Event = state.MSG_CHILD_SA
				o.fsm.Event(evt)
			case protocol.INFORMATIONAL:
				// TODO - it can be an error
				// handle in all states ?
				if err := o.handleEncryptedMessage(msg); err != nil {
					log.Error(err)
				}
				if del := msg.Payloads.Get(protocol.PayloadTypeD); del != nil {
					dp := del.(*protocol.DeletePayload)
					if dp.ProtocolId == protocol.IKE {
						log.Infof("Peer removed IKE SA : %#x", msg.IkeHeader.SpiI)
						evt.Event = state.DELETE_IKE_SA
						o.fsm.Event(evt)
					}
					for _, spi := range dp.Spis {
						if dp.ProtocolId == protocol.ESP {
							log.Info("removed ESP SA : %#x", spi)
							// TODO
						}
					}
				} // del
				// TODO - notification & cp
			} // ExchangeType
		} // select
	} // for
}

func (o *Session) Close() {
	log.Info("Close Session")
	o.fsm.Event(state.StateEvent{Event: state.FAIL, Data: errors.New("Session Closed")})
}

func (o *Session) InstallSa() (s state.StateEvent) {
	if err := o.addSa(); err != nil {
		s.Event = state.FAIL
		s.Data = err
	}
	return
}
func (o *Session) RemoveSa() (s state.StateEvent) {
	o.SendIkeSaDelete()
	o.removeSa()
	return
}
func (o *Session) StartRetryTimeout() (s state.StateEvent) {
	return
}
func (o *Session) Finished() (s state.StateEvent) {
	o.conn.Close()
	close(o.messages)
	log.Info("Finishing; cancel context")
	o.cancel(context.Canceled)
	return // not used
}

func (o *Session) checkSa(m *Message) (err error) {
	// check transport mode, and other info payloads
	wantsTransportMode := false
	for _, ns := range m.Payloads.GetNotifications() {
		switch ns.NotificationType {
		case protocol.AUTH_LIFETIME:
			lft := ns.NotificationMessage.(time.Duration)
			reauth := lft - 2*time.Second
			if lft <= 2*time.Second {
				reauth = 0
			}
			log.Infof("Lifetime: %s; reauth in %s", lft, reauth)
			time.AfterFunc(reauth, func() {
				o.fsm.Event(state.StateEvent{Event: state.REKEY_START})
				// o.fsm.Event(state.StateEvent{Event: state.MSG_IKE_REKEY})
			})
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	if wantsTransportMode && o.cfg.IsTransportMode {
		log.Info("Using Transport Mode")
	} else {
		if wantsTransportMode {
			log.Info("Peer Configured Transport Mode")
			o.cfg.IsTransportMode = true
		} else if o.cfg.IsTransportMode {
			log.Info("Peer Rejected Transport Mode Config")
			o.cfg.IsTransportMode = false
		}
	}

	tsi := m.Payloads.Get(protocol.PayloadTypeTSi).(*protocol.TrafficSelectorPayload)
	tsr := m.Payloads.Get(protocol.PayloadTypeTSr).(*protocol.TrafficSelectorPayload)
	log.Infof("ESP SA Configured: %#x<=>%#x; Selectors: %s<=>%s", o.EspSpiI, o.EspSpiR, tsi.Selectors, tsr.Selectors)
	return
}

func (o *Session) addSa() (err error) {
	// sa processing
	espEi, espAi, espEr, espAr := o.tkm.IpsecSaCreate(o.IkeSpiI, o.IkeSpiR)
	SpiI, _ := packets.ReadB32(o.EspSpiI, 0)
	SpiR, _ := packets.ReadB32(o.EspSpiR, 0)
	sa := &platform.SaParams{
		Src:             o.local,
		Dst:             o.remote,
		SrcPort:         0,
		DstPort:         0,
		SrcNet:          &net.IPNet{o.local, net.CIDRMask(32, 32)},
		DstNet:          &net.IPNet{o.remote, net.CIDRMask(32, 32)},
		EspEi:           espEi,
		EspAi:           espAi,
		EspEr:           espEr,
		EspAr:           espAr,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: o.cfg.IsTransportMode,
	}
	if err = platform.InstallChildSa(sa); err != nil {
		log.Error("Error installing child SA: %s", err)
		return err
	}
	log.Info("Installed child SA")
	return
}

func (o *Session) removeSa() (err error) {
	// sa processing
	SpiI, _ := packets.ReadB32(o.EspSpiI, 0)
	SpiR, _ := packets.ReadB32(o.EspSpiR, 0)
	sa := &platform.SaParams{
		Src:             o.local,
		Dst:             o.remote,
		SrcPort:         0,
		DstPort:         0,
		SrcNet:          &net.IPNet{o.local, net.CIDRMask(32, 32)},
		DstNet:          &net.IPNet{o.remote, net.CIDRMask(32, 32)},
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: o.cfg.IsTransportMode,
	}
	if err = platform.RemoveChildSa(sa); err != nil {
		log.Error("Error removing child SA: %s", err)
		return err
	} else {
		log.Info("Removed child SA")
	}
	return
}

func (o *Session) Notify(ie protocol.IkeError) {
	spi := o.IkeSpiI
	if o.tkm.isInitiator {
		spi = o.IkeSpiR
	}
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.IkeSpiI,
		spiR:        o.IkeSpiR,
		payload: &protocol.NotifyPayload{
			PayloadHeader:    &protocol.PayloadHeader{},
			ProtocolId:       protocol.IKE,
			NotificationType: protocol.NotificationType(ie),
			Spi:              spi,
		},
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
	}
	o.msgId++
}

func (o *Session) SendIkeSaDelete() {
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.IkeSpiI,
		spiR:        o.IkeSpiR,
		payload: &protocol.DeletePayload{
			PayloadHeader: &protocol.PayloadHeader{},
			ProtocolId:    protocol.IKE,
			Spis:          []protocol.Spi{},
		},
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
	}
	o.msgId++
}

func (o *Session) SendEmptyInformational() {
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.IkeSpiI,
		spiR:        o.IkeSpiR,
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
	}
	o.msgId++
}

func (o *Session) HandleSaRekey(msg interface{}) {
	o.fsm.Event(state.StateEvent{Event: state.DELETE_IKE_SA})
}
func (o *Session) SendIkeSaRekey() {
	o.fsm.Event(state.StateEvent{Event: state.DELETE_IKE_SA})
}

func (o *Session) handleEncryptedMessage(m *Message) (err error) {
	if m.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		var b []byte
		if b, err = o.tkm.VerifyDecrypt(m.Data); err != nil {
			return err
		}
		sk := m.Payloads.Get(protocol.PayloadTypeSK)
		if err = m.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return err
		}
	}
	return
}
