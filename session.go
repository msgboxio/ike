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

	initIb, initRb []byte

	events   chan stateEvents
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
		case evt := <-o.events:
			// sa processing
			espEi, espAi, espEr, espAr := o.tkm.IpsecSaCreate(o.cfg.IkeSpiI, o.cfg.IkeSpiR)
			SpiI, _ := packets.ReadB32(o.cfg.EspSpiI, 0)
			SpiR, _ := packets.ReadB32(o.cfg.EspSpiR, 0)
			sa := &platform.SaParams{
				Src:     o.local,
				Dst:     o.remote,
				SrcPort: 0,
				DstPort: 0,
				SrcNet:  &net.IPNet{o.local, net.CIDRMask(32, 32)},
				DstNet:  &net.IPNet{o.remote, net.CIDRMask(32, 32)},
				EspEi:   espEi,
				EspAi:   espAi,
				EspEr:   espEr,
				EspAr:   espAr,
				SpiI:    int(SpiI),
				SpiR:    int(SpiR),
			}
			switch evt {
			case installChildSa:
				if err := platform.InstallChildSa(sa); err != nil {
					log.Error("Error installing child SA: %v", err)
					o.cancel(err)
					break done
				}
				log.Info("Installed child SA")
			case removeChildSa:
				if err := platform.RemoveChildSa(sa); err != nil {
					log.Error("Error removing child SA: %v", err)
				} else {
					log.Info("Removed child SA")
				}
				o.fsm.PostEvent(state.IkeEvent{Id: state.DELETE_IKE_SA})
			}
		case msg := <-o.messages:
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
				evt.Id = state.IKE_REKEY
				o.fsm.PostEvent(evt)
			case INFORMATIONAL:
				// handle in all states ?
				o.handleInformational(msg)
			}
		}
	}
	o.conn.Close()
	close(o.events)
	close(o.messages)
}

func (o *Session) InstallChildSa() { o.events <- installChildSa }
func (o *Session) RemoveSa()       { o.events <- removeChildSa }

func (o *Session) DownloadCrl() {}

// close session
func (o *Session) HandleSaDead() {
	log.Info("close session")
	o.cancel(context.Canceled)
}

func (o *Session) Notify(ie IkeError) {}

func (o *Session) SendSaDelete() {
	spi := o.cfg.IkeSpiI
	if o.tkm.isInitiator {
		spi = o.cfg.IkeSpiR
	}
	// INFORMATIONAL
	info := makeInformational(infoParams{
		isInitiator: o.tkm.isInitiator,
		spiI:        o.cfg.IkeSpiI,
		spiR:        o.cfg.IkeSpiR,
		payload: &DeletePayload{
			PayloadHeader: &PayloadHeader{NextPayload: PayloadTypeNone},
			ProtocolId:    IKE,
			Spis:          []Spi{spi},
		},
	})
	info.IkeHeader.MsgId = o.msgId
	if _, err := EncodeTx(info, o.tkm, o.conn, o.conn.RemoteAddr(), true); err != nil {
		log.Error(err)
	}
	o.msgId++
}

func (o *Session) SendSaRekey() {
	// CREATE_CHILD_SA
}

func (o *Session) HandleSaRekey(msg interface{}) {
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		return
	}
	// TODO - reject
}

func (o *Session) handleInformational(msg *Message) (err error) {
	if err = o.handleEncryptedMessage(msg); err != nil {
		return err
	}
	if del := msg.Payloads.Get(PayloadTypeD); del != nil {
		dp := del.(*DeletePayload)
		if dp.ProtocolId == IKE {
			log.Infof("Peer removed IKE SA : %#x", msg.IkeHeader.SpiI)
			o.fsm.PostEvent(state.IkeEvent{Id: state.IKE_SA_DELETE_REQUEST})
		}
		for _, spi := range dp.Spis {
			if dp.ProtocolId == ESP {
				log.Info("removed ESP SA : %#x", spi)
				// TODO
			}
		}
	}
	return
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
