package ike

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"

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

// Session is closed by us by
// 1> calling Close() it sends a N[D] if not already closing
// 2> We wait for N[D], then remove SA
// 3> move to finished
// When receive N[D]
// 1> we remove SA
// 2> call Close() which sends N[D]
// 3> move to finished
type Session struct {
	context.Context
	cancel context.CancelFunc
	*state.Fsm

	isClosing bool

	tkm *Tkm
	cfg *Config

	idRemote, idLocal Identity
	remote, local     net.IP

	IkeSpiI, IkeSpiR protocol.Spi
	EspSpiI, EspSpiR protocol.Spi

	incoming chan *Message
	outgoing chan []byte

	msgId uint32

	initIb, initRb []byte
}

// Housekeeping

func (o *Session) Run(pconn *ipv4.PacketConn, to net.Addr) {
	for {
		select {
		case reply, ok := <-o.outgoing:
			if !ok {
				break
			}
			if err := WritePacket(pconn, reply, to); err != nil {
				o.Close(err)
				break
			}
		case msg, ok := <-o.incoming:
			if !ok {
				break
			}
			if evt := o.handleMessage(msg); evt != nil {
				o.PostEvent(*evt)
			}
		case evt, ok := <-o.Events():
			if !ok {
				break
			}
			o.HandleEvent(evt)
		case <-o.Done():
			log.Infof("Finished IKE SA : %#x => %#x", o.IkeSpiI, o.IkeSpiR)
			return
		}
	}
}

// Close is called to shutdown this session
func (o *Session) Close(err error) {
	log.Info("Close Session")
	if o.isClosing {
		return
	}
	o.isClosing = true
	// send to peer, peer should send SA_DELETE message
	o.SendIkeSaDelete()
	// TODO - start timeout to delete sa if peers does not reply
	o.PostEvent(state.StateEvent{Event: state.DELETE_IKE_SA, Data: err})
}

func (o *Session) PostMessage(m *Message) {
	if err := o.isMessageValid(m); err != nil {
		log.Error("Drop Message: ", err)
		return
	}
	if o.isClosing {
		log.Error("Drop Message: Closing")
		return
	}
	o.incoming <- m
}

func (o *Session) handleMessage(msg *Message) (evt *state.StateEvent) {
	evt = &state.StateEvent{Data: msg}
	// make sure they are responses - TODO
	switch msg.IkeHeader.ExchangeType {
	case protocol.IKE_SA_INIT:
		evt.Event = state.MSG_INIT
		return
	case protocol.IKE_AUTH:
		evt.Event = state.MSG_AUTH
		return
	case protocol.CREATE_CHILD_SA:
		evt.Event = state.MSG_CHILD_SA
		return
	case protocol.INFORMATIONAL:
		// TODO - it can be an error
		// handle in all states ?
		if err := o.handleEncryptedMessage(msg); err != nil {
			log.Error(err)
		}
		if del := msg.Payloads.Get(protocol.PayloadTypeD); del != nil {
			dp := del.(*protocol.DeletePayload)
			if dp.ProtocolId == protocol.IKE {
				log.Infof("Peer remove IKE SA : %#x", msg.IkeHeader.SpiI)
				evt.Event = state.MSG_DELETE_IKE_SA
				return
			}
			for _, spi := range dp.Spis {
				if dp.ProtocolId == protocol.ESP {
					log.Infof("Peer remove ESP SA : %#x", spi)
					// TODO
				}
			}
		} // del
		if note := msg.Payloads.Get(protocol.PayloadTypeN); note != nil {
			np := note.(*protocol.NotifyPayload)
			if err, ok := protocol.GetIkeErrorCode(np.NotificationType); ok {
				log.Errorf("Received Error: %v", err)
				evt.Event = state.FAIL
				evt.Data = np.NotificationType
				return
			}
		}
	}
	return nil
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
	removeSa(o.tkm,
		o.IkeSpiI, o.IkeSpiR,
		o.EspSpiI, o.EspSpiR,
		o.cfg,
		o.local, o.remote)
	o.Close(context.Canceled)
	return
}

func (o *Session) StartRetryTimeout() (s state.StateEvent) {
	return
}

// Finished is called by state machine upon entering finished state
func (o *Session) Finished() (s state.StateEvent) {
	close(o.incoming)
	if queued := len(o.outgoing); queued > 0 {
		// TODO : let the queue drain
		log.Warningf("Finished; may drop messages: %s", queued)
	}
	close(o.outgoing)
	o.CloseEvents()
	log.Info("Finished; cancel context")
	o.cancel(context.Canceled)
	return // not used
}

// handlers

func (o *Session) CheckSa(m interface{}) (s state.StateEvent) {
	// get message
	msg := m.(*Message)
	// get peer spi
	if espSpi, err := getPeerSpi(msg, protocol.ESP); err != nil {
		log.Error(err)
		s.Data = err
		return
	} else {
		if o.tkm.isInitiator {
			o.EspSpiR = append([]byte{}, espSpi...)
		} else {
			o.EspSpiI = append([]byte{}, espSpi...)
		}
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
			log.Infof("Lifetime: %s; reauth in %s", lft, reauth)
			time.AfterFunc(reauth, func() {
				o.PostEvent(state.StateEvent{Event: state.REKEY_START})
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
			err := errors.New("Peer Rejected Transport Mode Config")
			log.Error(err)
			s.Data = err
		}
	}
	// load additional configs
	if err := o.cfg.AddFromAuth(msg); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - check IPSEC selectors & config
	s.Event = state.SUCCESS
	return
}

func (o *Session) HandleCreateChildSa(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		// send NO_ADDITIONAL_SAS
		s.Data = protocol.NO_ADDITIONAL_SAS
		return
	}
	if err := m.EnsurePayloads(InitPayloads); err == nil {
		log.Infof("peer requests IKE rekey")
	} else {
		log.Infof("peer requests IPSEC rekey")
	}
	s.Data = protocol.NO_ADDITIONAL_SAS
	return
}

// CheckError checks for received errors from local actions & checks
func (o *Session) CheckError(msg interface{}) (s state.StateEvent) {
	if notif, ok := msg.(protocol.NotificationType); ok {
		// check if the received notification was an error
		if _, ok := protocol.GetIkeErrorCode(notif); ok {
			// ignore it
			return
		}
	} else if iErr, ok := msg.(protocol.IkeErrorCode); ok {
		o.Notify(iErr)
		return
	}
	return
}

// utilities

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

// SendEmptyInformational can be used for periodic keepalive
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

func (o *Session) isMessageValid(m *Message) error {
	if spi := m.IkeHeader.SpiI; !bytes.Equal(spi, o.IkeSpiI) {
		return fmt.Errorf("different initiator Spi %s", spi)
	}
	// Dont check Responder SPI. initiator IKE_INTI does not have it
	if !o.remote.Equal(AddrToIp(m.RemoteAddr)) {
		return fmt.Errorf("different remote IP %v vs %v", o.remote, m.RemoteAddr)
	}
	// local IP is not set initially for initiator
	if o.local == nil {
		o.local = m.LocalIp
	} else if !o.local.Equal(m.LocalIp) {
		return fmt.Errorf("different local IP %v vs %v", o.local, m.LocalIp)
	}
	return nil
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
