package ike

import (
	"net"

	"msgbox.io/context"
	"msgbox.io/ike/platform"
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

	IkeSpiI, IkeSpiR Spi
	EspSpiI, EspSpiR Spi

	newIkeSpiI, newIkeSpiR Spi
	newTkm                 *Tkm

	initIb, initRb []byte

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
			evt := state.IkeEvent{Message: msg}
			// make sure they are responses - TODO
			switch msg.IkeHeader.ExchangeType {
			case IKE_SA_INIT:
				evt.Id = state.IKE_SA_INIT
				o.fsm.PostEvent(evt)
			case IKE_AUTH:
				evt.Id = state.IKE_AUTH
				o.fsm.PostEvent(evt)
			case CREATE_CHILD_SA:
				evt.Id = state.CREATE_CHILD_SA
				o.fsm.PostEvent(evt)
			case INFORMATIONAL:
				// handle in all states ?
				if err := o.handleEncryptedMessage(msg); err != nil {
					log.Error(err)
				}
				if del := msg.Payloads.Get(PayloadTypeD); del != nil {
					dp := del.(*DeletePayload)
					if dp.ProtocolId == IKE {
						log.Infof("Peer removed IKE SA : %#x", msg.IkeHeader.SpiI)
						o.fsm.PostEvent(state.IkeEvent{Id: state.DELETE_IKE_SA})
					}
					for _, spi := range dp.Spis {
						if dp.ProtocolId == ESP {
							log.Info("removed ESP SA : %#x", spi)
							// TODO
						}
					}
				} // del
			} // ExchangeType
		} // select
	} // for
}

func (o *Session) Close() {
	log.Info("close")
	o.fsm.PostEvent(state.IkeEvent{Id: state.MSG_DELETE_IKE_SA})
}

func (o *Session) InstallChildSa() {
	if err := o.handleSaEvent(installChildSa); err != nil {
		o.cancel(err)
	}
}
func (o *Session) RemoveSa() { o.handleSaEvent(removeChildSa) }

func (o *Session) handleSaEvent(evt stateEvents) (err error) {
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
	switch evt {
	case installChildSa:
		if err := platform.InstallChildSa(sa); err != nil {
			log.Error("Error installing child SA: %s", err)
			return err
		}
		log.Info("Installed child SA")
	case removeChildSa:
		if err := platform.RemoveChildSa(sa); err != nil {
			log.Error("Error removing child SA: %s", err)
			return err
		} else {
			log.Info("Removed child SA")
		}
	}
	return
}

func (o *Session) DownloadCrl() {}

// close session
func (o *Session) HandleSaDead() {
	o.conn.Close()
	close(o.messages)
	log.Info("cancel context")
	o.cancel(context.Canceled)
}

func (o *Session) Notify(ie IkeError) {
	spi := o.IkeSpiI
	if o.tkm.isInitiator {
		spi = o.IkeSpiR
	}
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.IkeSpiI,
		spiR:        o.IkeSpiR,
		payload: &NotifyPayload{
			PayloadHeader:    &PayloadHeader{NextPayload: PayloadTypeNone},
			ProtocolId:       IKE,
			NotificationType: NotificationType(ie),
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
		payload: &DeletePayload{
			PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNone},
			ProtocolId:    IKE,
			Spis:          []Spi{},
		},
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
	}
	o.msgId++
}

func (o *Session) handleEncryptedMessage(m *Message) (err error) {
	if m.IkeHeader.NextPayload == PayloadTypeSK {
		var b []byte
		if b, err = o.tkm.VerifyDecrypt(m.Data); err != nil {
			return err
		}
		sk := m.Payloads.Get(PayloadTypeSK)
		if err = m.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return err
		}
	}
	return
}
