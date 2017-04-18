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

// DecodeMessage decodes an keeps the message buffer for later decryption
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

// DecryptMessage uses crypto keys to decode & verify the message
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

// Encode encodes the message using crypto keys
func (s *Message) Encode(tkm *Tkm, forInitiator bool, log log.Logger) (b []byte, err error) {
	level.Debug(log).Log("tx:" + spew.Sprintf("%#v", s))
	log.Log("sending", fmt.Sprintf("[%d] %s%s", s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags),
		"payloads", s.Payloads)
	firstPayloadType := protocol.PayloadTypeNone // no payloads are one possibility
	if len(s.Payloads.Array) > 0 {
		firstPayloadType = s.Payloads.Array[0].Type()
	}
	nextPayload := s.IkeHeader.NextPayload
	if nextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant encrypt, no tkm found")
			return
		}
		payload := protocol.EncodePayloads(s.Payloads, log)
		plen := len(payload) + tkm.CryptoOverhead(payload)
		// sk payload header
		skph := protocol.PayloadHeader{
			NextPayload:   firstPayloadType,
			PayloadLength: uint16(plen),
		}.Encode(log)
		// prepare proper ike header
		s.IkeHeader.MsgLength = uint32(protocol.IKE_HEADER_LEN + len(skph) + plen)
		// finally ask the tkm to apply secrets
		b, err = tkm.EncryptMac(append(append(s.IkeHeader.Encode(log), skph...), payload...), forInitiator)
	} else {
		b = protocol.EncodePayloads(s.Payloads, log)
		s.IkeHeader.NextPayload = firstPayloadType
		s.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(s.IkeHeader.Encode(log), b...)
	}
	return
}
