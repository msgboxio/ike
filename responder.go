package ike

import (
	"errors"
	"net"

	"msgbox.io/context"
	"msgbox.io/log"
)

type Responder struct {
	context.Context
	cancel context.CancelFunc

	conn              net.Conn
	remote            net.Addr
	remoteIP, localIP net.IP

	tkm *Tkm
	cfg *ClientCfg

	initIb, initRb []byte

	Messages chan *Message
}

func NewResponder(parent context.Context, ids Identities, conn net.Conn, remote net.Addr, remoteIP, localIP net.IP, initI *Message) (*Responder, error) {
	cxt, cancel := context.WithCancel(parent)

	if !EnsurePayloads(initI, InitPayloads) {
		err := errors.New("essential payload is missing from init message")
		cancel(err)
		return nil, err
	}
	tkm, err := newTkmFromInit(initI, ids)
	if err != nil {
		cancel(err)
		return nil, err
	}
	cfg, err := NewClientConfigFromInit(initI)
	if err != nil {
		cancel(err)
		return nil, err
	}
	o := &Responder{
		Context:  cxt,
		cancel:   cancel,
		conn:     conn,
		remote:   remote,
		remoteIP: remoteIP,
		localIP:  localIP,
		tkm:      tkm,
		cfg:      cfg,
		// events:   make(chan stateEvents, 10),
		Messages: make(chan *Message, 10),
	}
	go runResponder(o)
	return o, nil
}

func runResponder(o *Responder) {
	var err error
done:
	for {
		select {
		case <-o.Done():
			break done
		case msg := <-o.Messages:
			switch msg.IkeHeader.ExchangeType {
			case IKE_SA_INIT:
				o.initIb = msg.Data
				// make response message
				initR := makeInit(initParams{
					isInitiator:   o.tkm.isInitiator,
					spiI:          o.cfg.IkeSpiI,
					spiR:          o.cfg.IkeSpiR,
					proposals:     []*SaProposal{o.cfg.ProposalIke},
					nonce:         o.tkm.Nr,
					dhTransformId: o.tkm.suite.dhGroup.DhTransformId,
					dhPublic:      o.tkm.DhPublic,
				})
				// encode & send
				o.initRb, err = EncodeTx(initR, nil, o.conn, o.remote, false)
				if err != nil {
					break done
				}
				// check spiR is still correct
				o.tkm.IsaCreate(o.cfg.IkeSpiI, o.cfg.IkeSpiR)
				log.Infof("IKE SA Established: %#x<=>%#x", o.cfg.IkeSpiI, o.cfg.IkeSpiR)
			case IKE_AUTH:
				// decrypt
				if err = o.handleEncryptedMessage(msg); err != nil {
					log.Error(err)
					continue
				}
				if !EnsurePayloads(msg, AuthIPayloads) {
					err := errors.New("essential payload is missing from auth message")
					log.Error(err)
					continue
				}
				// authenticate peer
				if !authenticateI(msg, o.initIb, o.tkm) {
					err := errors.New("could not authenticate")
					log.Error(err)
					continue
				}
				ipsecSa := msg.Payloads.Get(PayloadTypeSA).(*SaPayload)
				tsI := msg.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload).Selectors
				tsR := msg.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload).Selectors
				// responder's signed octet
				// initR | Ni | prf(sk_pr | IDr )
				signed1 := append(o.initRb, o.tkm.Ni.Bytes()...)
				authR := makeAuth(o.cfg.IkeSpiI, o.cfg.IkeSpiR, ipsecSa.Proposals, tsI, tsR, signed1, o.tkm)
				_, err = EncodeTx(authR, o.tkm, o.conn, o.remote, false)
				if err != nil {
					log.Error(err)
					continue
				}
				log.Infof("ESP SA Established: %#x<=>%#x; Selectors: %s<=>%s", o.cfg.EspSpiI, o.cfg.EspSpiR, tsI.Selectors, tsR.Selectors)
			case INFORMATIONAL:
			}
		}
	}
	o.cancel(err)
	o.conn.Close()
	close(o.Messages)
}

func (o *Responder) handleEncryptedMessage(m *Message) (err error) {
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
