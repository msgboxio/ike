package ike

import (
	"io"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var (
	InitPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeKE,
		protocol.PayloadTypeNonce,
	}

	AuthIPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDi,
		protocol.PayloadTypeAUTH,
	}
	AuthRPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDr,
		protocol.PayloadTypeAUTH,
	}
	SaPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}

	RekeyIkeSaPaylods = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeKE,
		protocol.PayloadTypeNonce,
	}

	RekeyChildSaPaylods = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeNonce,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
)

type Message struct {
	IkeHeader             *protocol.IkeHeader
	Payloads              *protocol.Payloads
	LocalAddr, RemoteAddr net.Addr

	Data []byte // used to carry raw bytes
}

func DecodeMessage(b []byte, log *logrus.Logger) (msg *Message, err error) {
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

func (s *Message) DecodeHeader(b []byte, log *logrus.Logger) (err error) {
	s.IkeHeader, err = protocol.DecodeIkeHeader(b, log)
	return
}

func (s *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType, log *logrus.Logger) (err error) {
	if s.Payloads, err = protocol.DecodePayloads(b, nextPayload, log); err != nil {
		return
	}
	if log.Level == logrus.DebugLevel {
		log.Debug("Rx:\n" + spew.Sdump(s))
	} else {
		log.Infof("[%d]Received %s%s: payloads %s",
			s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags, *s.Payloads)
	}
	return
}

func (s *Message) Encode(tkm *Tkm, forInitiator bool, log *logrus.Logger) (b []byte, err error) {
	if log.Level == logrus.DebugLevel {
		log.Debug("Tx:\n" + spew.Sdump(s))
	} else {
		log.Infof("[%d]Sending %s%s: payloads %s",
			s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags, s.Payloads)
	}
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
		// payload header
		ph := protocol.PayloadHeader{
			NextPayload:   firstPayloadType,
			PayloadLength: uint16(plen),
		}.Encode(log)
		// prepare proper ike header
		s.IkeHeader.MsgLength = uint32(protocol.IKE_HEADER_LEN + len(ph) + plen)
		// encode ike header, and add to protocol header
		headers := append(s.IkeHeader.Encode(log), ph...)
		// finally ask the tkm to apply secrets
		b, err = tkm.EncryptMac(headers, payload, forInitiator)
	} else {
		b = protocol.EncodePayloads(s.Payloads, log)
		s.IkeHeader.NextPayload = firstPayloadType
		s.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(s.IkeHeader.Encode(log), b...)
	}
	return
}

func (msg *Message) EnsurePayloads(payloadTypes []protocol.PayloadType) error {
	mp := msg.Payloads
	for _, pt := range payloadTypes {
		if mp.Get(pt) == nil {
			return errors.Errorf("essential payload %s is missing from %s message",
				pt, msg.IkeHeader.ExchangeType)
		}
	}
	return nil
}
