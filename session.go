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

	idRemote, idLocal Identities
	remote, local     net.IP

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
	// IKE_AUTH
	// make sure selectors are present
	if o.cfg.TsI == nil || o.cfg.TsR == nil {
		log.Infoln("Adding host based selectors")
		// add host based selectors by default
		slen := len(o.local) * 8
		ini := o.remote
		res := o.local
		if o.tkm.isInitiator {
			ini = o.local
			res = o.remote
		}
		o.cfg.AddSelector(
			&net.IPNet{IP: ini, Mask: net.CIDRMask(slen, slen)},
			&net.IPNet{IP: res, Mask: net.CIDRMask(slen, slen)})
	}
	log.Infof("SA selectors: [INI]%s<=>%s[RES]", o.cfg.TsI, o.cfg.TsR)

	// proposal
	var prop []*protocol.SaProposal
	// part of signed octet
	var initB []byte
	if o.tkm.isInitiator {
		prop = ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, o.EspSpiI)
		// intiators's signed octet
		// initI | Nr | prf(sk_pi | IDi )
		initB = o.initIb
	} else {
		prop = ProposalFromTransform(protocol.ESP, o.cfg.ProposalEsp, o.EspSpiR)
		// responder's signed octet
		// initR | Ni | prf(sk_pr | IDr )
		initB = o.initRb
	}
	auth := makeAuth(
		&authParams{
			o.tkm.isInitiator,
			o.cfg.IsTransportMode,
			o.IkeSpiI, o.IkeSpiR,
			prop, o.cfg.TsI, o.cfg.TsR,
			&psk{o.tkm, o.idLocal},
		}, initB)
	auth.IkeHeader.MsgId = o.msgId
	// encode
	return o.sendMsg(auth.Encode(o.tkm))
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

// handlers

func (o *Session) HandleIkeSaInit(msg interface{}) (s state.StateEvent) {
	s.Event = state.INIT_FAIL
	// response
	m := msg.(*Message)
	// we know what IKE ciphersuite peer selected
	// generate keys necessary for IKE SA protection and encryption.
	// check NAT-T payload to determine if there is a NAT between the two peers
	// If there is, then all the further communication is perfomed over port 4500 instead of the default port 500
	// also, periodically send keepalive packets in order for NAT to keep it’s bindings alive.
	// find traffic selectors
	// send IKE_AUTH req
	if err := m.EnsurePayloads(InitPayloads); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := m.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	if err := o.tkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	// set Nr
	if o.tkm.isInitiator {
		no := m.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
		o.tkm.Nr = no.Nonce
	}
	// set spiR
	o.IkeSpiR = append([]byte{}, m.IkeHeader.SpiR...)
	// create rest of ike sa
	o.tkm.IsaCreate(o.IkeSpiI, o.IkeSpiR, nil)
	log.Infof("IKE SA INITIALISED: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	// save Data
	if o.tkm.isInitiator {
		o.initRb = m.Data
	} else {
		o.initIb = m.Data
	}
	s.Event = state.SUCCESS
	return
}

func (o *Session) HandleIkeAuth(msg interface{}) (s state.StateEvent) {
	s.Event = state.AUTH_FAIL
	// response
	m := msg.(*Message)
	if err := o.handleEncryptedMessage(m); err != nil {
		log.Error(err)
		s.Data = err
		return
	}
	payloads := AuthIPayloads
	if o.tkm.isInitiator {
		payloads = AuthRPayloads
	}
	if err := m.EnsurePayloads(payloads); err != nil {
		// notification is recoverable
		for _, n := range m.Payloads.GetNotifications() {
			if err, ok := protocol.GetIkeErrorCode(n.NotificationType); ok {
				s.Data = err
				return
			}
		}
		log.Error(err)
		s.Data = err
		return
	}
	// authenticate peer
	authPeer := authenticateI
	init := o.initIb
	if o.tkm.isInitiator {
		authPeer = authenticateR
		init = o.initRb
	}
	if !authPeer(m, init, o.tkm, o.idRemote) {
		log.Error(protocol.AUTHENTICATION_FAILED)
		s.Data = protocol.AUTHENTICATION_FAILED
		return
	}
	log.Infof("IKE SA CREATED: [%s]%#x<=>%#x[%s]",
		o.local,
		o.IkeSpiI,
		o.IkeSpiR,
		o.remote)
	s.Event = state.SUCCESS
	// move to STATE_MATURE state
	o.fsm.Event(state.StateEvent{Event: state.SUCCESS, Data: m})
	return
}

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

// utilities

func (o *Session) Close(err error) {
	log.Info("Close Session")
	if o.isClosing {
		return
	}
	// send to peer, peer should send SA_DELETE message
	o.SendIkeSaDelete()
	// TODO - start timeout to delete sa if peers does not reply
	o.fsm.Event(state.StateEvent{Event: state.DELETE_IKE_SA, Data: err})
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
