package ike

import (
	"bytes"
	"net"
	"time"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

type stateEvents int

const (
	installChildSa stateEvents = iota + 1
	removeChildSa
)

type Session struct {
	context.Context
	cancel context.CancelFunc

	isResponder bool

	tkm *Tkm
	cfg *ClientCfg

	remote, local net.IP

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	incoming chan *Message
	outgoing chan []byte

	fsm *state.Fsm

	msgId uint32

	initIb, initRb []byte
}

func (o *Session) HandleMessage(m *Message) {
	// check spis
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		log.Errorf("different initiator Spi %s", spi)
		return
	}
	// Dont check Responder SPI. initiator IKE_INTI does not have it
	if !o.remote.Equal(m.RemoteIp) {
		log.Errorf("different remote IP %v vs %v", o.remote, m.RemoteIp)
		return
	}
	// local IP is not set initially for initiator
	if o.local == nil {
		o.local = m.LocalIp
	} else if !o.local.Equal(m.LocalIp) {
		log.Errorf("different local IP %v vs %v", o.local, m.LocalIp)
		return
	}
	o.incoming <- m
}
func (o *Session) Replies() <-chan []byte { return o.outgoing }

func run(o *Session) {
done:
	for {
		select {
		case <-o.Done():
			break done
		case msg, ok := <-o.incoming:
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
				if note := msg.Payloads.Get(protocol.PayloadTypeN); note != nil {
					np := note.(*protocol.NotifyPayload)
					if err, ok := protocol.GetIkeError(np.NotificationType); ok {
						log.Errorf("Received Error: %v", err)
						evt.Event = state.FAIL
						evt.Data = err
						o.fsm.Event(evt)
					}
				}
				// TODO cp
			} // ExchangeType
		} // select
	} // for
}

func (o *Session) Close(err error) {
	log.Info("Close Session")
	o.fsm.Event(state.StateEvent{Event: state.FAIL, Data: err})
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
	close(o.incoming)
	if len(o.outgoing) > 0 {
		// let the queue drain
		time.Sleep(100 * time.Millisecond)
	}
	close(o.outgoing)
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
	return
}

func (o *Session) addSa() (err error) {
	// sa processing
	espEi, espAi, espEr, espAr := o.tkm.IpsecSaCreate(o.IkeSpiI, o.IkeSpiR)
	SpiI, _ := packets.ReadB32(o.EspSpiI, 0)
	SpiR, _ := packets.ReadB32(o.EspSpiR, 0)
	tsI := o.cfg.TsI[0]
	tsR := o.cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	// print config
	log.Infof("Installing Child SA: %#x<=>%#x; Selectors: %s<=>%s", o.EspSpiI, o.EspSpiR, iNet, rNet)
	sa := &platform.SaParams{
		Src:             o.local,
		Dst:             o.remote,
		SrcPort:         0,
		DstPort:         0,
		SrcNet:          iNet,
		DstNet:          rNet,
		EspEi:           espEi,
		EspAi:           espAi,
		EspEr:           espEr,
		EspAr:           espAr,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: o.cfg.IsTransportMode,
	}
	if o.isResponder {
		sa.SrcNet = rNet
		sa.DstNet = iNet
	}
	if err = platform.InstallChildSa(sa); err != nil {
		return err
	}
	log.Info("Installed Child SA")
	return
}

func (o *Session) removeSa() (err error) {
	// sa processing
	SpiI, _ := packets.ReadB32(o.EspSpiI, 0)
	SpiR, _ := packets.ReadB32(o.EspSpiR, 0)
	tsI := o.cfg.TsI[0]
	tsR := o.cfg.TsR[0]
	iNet := FirstLastAddressToIPNet(tsI.StartAddress, tsI.EndAddress)
	rNet := FirstLastAddressToIPNet(tsR.StartAddress, tsR.EndAddress)
	sa := &platform.SaParams{
		Src:             o.local,
		Dst:             o.remote,
		SrcPort:         0,
		DstPort:         0,
		SrcNet:          iNet,
		DstNet:          rNet,
		SpiI:            int(SpiI),
		SpiR:            int(SpiR),
		IsTransportMode: o.cfg.IsTransportMode,
	}
	if o.isResponder {
		sa.SrcNet = rNet
		sa.DstNet = iNet
	}
	if err = platform.RemoveChildSa(sa); err != nil {
		log.Error("Error removing child SA: %s", err)
		return err
	} else {
		log.Info("Removed child SA")
	}
	return
}

func (o *Session) CheckError(m interface{}) (s state.StateEvent) {
	// evt := m.(state.StateEvent)
	o.Notify(protocol.ERR_INVALID_SYNTAX)
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
	// encode & send
	infoB, err := info.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		return
	}
	o.outgoing <- infoB
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
	// encode & send
	infoB, err := info.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		return
	}
	o.outgoing <- infoB
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
	// encode & send
	infoB, err := info.Encode(o.tkm)
	if err != nil {
		log.Error(err)
		return
	}
	o.outgoing <- infoB
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
