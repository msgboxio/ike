package ike

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

type stateEvents int

const (
	installChildSa stateEvents = iota + 1
	removeChildSa
)

type Session struct {
	context.Context
	cancel    context.CancelFunc
	isClosing bool

	tkm *Tkm
	cfg *Config

	remote, local net.IP

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	incoming chan *Message
	outgoing chan []byte

	fsm *state.Fsm

	msgId uint32

	initIb, initRb []byte
}

func isMessageValid(m *Message, o *Session) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return fmt.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_INTI does not have it
	if !o.remote.Equal(m.RemoteIp) {
		return fmt.Errorf("different remote IP %v vs %v", o.remote, m.RemoteIp)
	}
	// local IP is not set initially for initiator
	if o.local == nil {
		o.local = m.LocalIp
	} else if !o.local.Equal(m.LocalIp) {
		return fmt.Errorf("different local IP %v vs %v", o.local, m.LocalIp)
	}
	return nil
}

func (o *Session) HandleMessage(m *Message) {
	if err := isMessageValid(m, o); err != nil {
		log.Error("Drop Message: ", err)
		return
	}
	if o.isClosing {
		log.Error("Drop Message: Closing")
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
					if err, ok := protocol.GetIkeErrorCode(np.NotificationType); ok {
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

func (o *Session) sendMsg(buf []byte, err error) (s state.StateEvent) {
	if err != nil {
		log.Error(err)
		s.Event = state.FAIL
		s.Data = err
		return
	}
	o.outgoing <- buf
	o.msgId++
	return
}

// callbacks

func (o *Session) SendInit() (s state.StateEvent) {
	initMsg := func() ([]byte, error) {
		initB, err := InitMsg(o.tkm, o.IkeSpiI, o.IkeSpiR, o.msgId, o.cfg)
		if err != nil {
			return nil, err
		}
		if o.tkm.isInitiator {
			o.initIb = initB
		} else {
			o.initRb = initB
		}
		return initB, nil
	}
	return o.sendMsg(initMsg())
}

func (o *Session) SendAuth() (s state.StateEvent) {
	return o.sendMsg(AuthMsg(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.initIb, o.initRb,
		o.msgId, o.cfg,
		o.local, o.remote))
}

func (o *Session) InstallSa() (s state.StateEvent) {
	if err := addSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.local, o.remote); err != nil {
		s.Event = state.FAIL
		s.Data = err
	}
	return
}
func (o *Session) RemoveSa() (s state.StateEvent) {
	o.SendIkeSaDelete()
	removeSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.local, o.remote)
	return
}

func (o *Session) StartRetryTimeout() (s state.StateEvent) {
	return
}

func (o *Session) Finished() (s state.StateEvent) {
	o.isClosing = true
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

// utilities

func (o *Session) Close(err error) {
	log.Info("Close Session")
	if o.isClosing {
		return
	}
	o.fsm.Event(state.StateEvent{Event: state.FAIL, Data: err})
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
			})
		case protocol.USE_TRANSPORT_MODE:
			wantsTransportMode = true
		}
	}
	if wantsTransportMode && o.cfg.IsTransportMode {
		log.Info("Using Transport Mode")
	} else {
		if wantsTransportMode {
			log.Info("Peer wanted Transport mode, forcing Tunnel mode")
		} else if o.cfg.IsTransportMode {
			log.Info("Peer Rejected Transport Mode Config")
			err = errors.New("Peer Rejected Transport Mode Config")
		}
	}
	return
}

func (o *Session) CheckError(msg interface{}) (s state.StateEvent) {
	if err, ok := msg.(protocol.NotificationType); ok {
		if iErr, ok := protocol.GetIkeErrorCode(err); ok {
			o.Notify(iErr)
			return
		}
	}
	o.Notify(protocol.ERR_INVALID_SYNTAX)
	return
}

func (o *Session) Notify(ie protocol.IkeErrorCode) {
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
	o.sendMsg(info.Encode(o.tkm))
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
	o.sendMsg(info.Encode(o.tkm))
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
	o.sendMsg(info.Encode(o.tkm))
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
