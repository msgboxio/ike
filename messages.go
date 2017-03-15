package ike

import (
	"fmt"
	"io"
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// Message carries data about the incoming or outgoing ike packet
type Message struct {
	IkeHeader             *protocol.IkeHeader
	Payloads              *protocol.Payloads
	LocalAddr, RemoteAddr net.Addr

	Data []byte // used to carry raw bytes
}

// DecodeHeader decodes the ike header and replaces the IkeHeader member
func (s *Message) DecodeHeader(b []byte, log log.Logger) (err error) {
	s.IkeHeader, err = protocol.DecodeIkeHeader(b, log)
	return
}

// DecodePayloads decodes & replaces the payloads member with list of decoded payloads
func (s *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType, log log.Logger) (err error) {
	if s.Payloads, err = protocol.DecodePayloads(b, nextPayload, log); err != nil {
		return
	}
	level.Debug(log).Log("rx" + spew.Sprintf("%#v", s))
	log.Log("received", fmt.Sprintf("[%d] %s%s", s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags),
		"payloads", *s.Payloads)
	return
}

func DecodeMessage(b []byte, log log.Logger) (msg *Message, err error) {
	msg = &Message{}
	if err = msg.DecodeHeader(b, log); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = io.ErrShortBuffer
		return
	}
	// further decode
	if err = msg.DecodePayloads(b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload, log); err != nil {
		return
	}
	// decrypt later
	msg.Data = b
	return
}

func DecryptMessage(m *Message, tkm *Tkm, forInitiator bool, log log.Logger) (err error) {
	if m.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		var b []byte
		if b, err = tkm.VerifyDecrypt(m.Data, forInitiator); err != nil {
			return err
		}
		sk := m.Payloads.Get(protocol.PayloadTypeSK)
		if err = m.DecodePayloads(b, sk.NextPayloadType(), log); err != nil {
			return err
		}
	}
	return
}

// EnsurePayloads checks if the needed paylaods are present in the message
func (s *Message) EnsurePayloads(payloadTypes []protocol.PayloadType) error {
	mp := s.Payloads
	for _, pt := range payloadTypes {
		if mp.Get(pt) == nil {
			return errors.Errorf("essential payload %s is missing from %s message",
				pt, s.IkeHeader.ExchangeType)
		}
	}
	return nil
}

func (msg *Message) Encode(tkm *Tkm, forInitiator bool, log log.Logger) (b []byte, err error) {
	level.Debug(log).Log("tx:" + spew.Sprintf("%#v", msg))
	log.Log("sending", fmt.Sprintf("[%d] %s%s", msg.IkeHeader.MsgId, msg.IkeHeader.ExchangeType, msg.IkeHeader.Flags),
		"payloads", msg.Payloads)
	firstPayloadType := protocol.PayloadTypeNone // no payloads are one possibility
	if len(msg.Payloads.Array) > 0 {
		firstPayloadType = msg.Payloads.Array[0].Type()
	}
	nextPayload := msg.IkeHeader.NextPayload
	if nextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant encrypt, no tkm found")
			return
		}
		payload := protocol.EncodePayloads(msg.Payloads, log)
		plen := len(payload) + tkm.CryptoOverhead(payload)
		// payload header
		ph := protocol.PayloadHeader{
			NextPayload:   firstPayloadType,
			PayloadLength: uint16(plen),
		}.Encode(log)
		// prepare proper ike header
		msg.IkeHeader.MsgLength = uint32(protocol.IKE_HEADER_LEN + len(ph) + plen)
		// encode ike header, and add to protocol header
		headers := append(msg.IkeHeader.Encode(log), ph...)
		// finally ask the tkm to apply secrets
		b, err = tkm.EncryptMac(headers, payload, forInitiator)
	} else {
		b = protocol.EncodePayloads(msg.Payloads, log)
		msg.IkeHeader.NextPayload = firstPayloadType
		msg.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(msg.IkeHeader.Encode(log), b...)
	}
	return
}
