package ike

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
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
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
	AuthRPayloads = []protocol.PayloadType{
		protocol.PayloadTypeIDr,
		protocol.PayloadTypeAUTH,
		protocol.PayloadTypeSA,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}

	NewChilSaIPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeNonce,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
	NewChilSaRPayloads = []protocol.PayloadType{
		protocol.PayloadTypeSA,
		protocol.PayloadTypeNonce,
	}

	RekeyIkeSaPaylods = InitPayloads

	RekeyChildSaIPaylods = []protocol.PayloadType{
		protocol.PayloadTypeN,
		protocol.PayloadTypeSA,
		protocol.PayloadTypeNonce,
		protocol.PayloadTypeTSi,
		protocol.PayloadTypeTSr,
	}
	RekeyChildSaRPaylods = []protocol.PayloadType{
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

func DecodeMessage(b []byte) (msg *Message, err error) {
	msg = &Message{}
	if err = msg.DecodeHeader(b); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = io.ErrShortBuffer
		return
	}
	// further decode
	if err = msg.DecodePayloads(b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
		return
	}
	// decrypt later
	msg.Data = b
	return
}

func (s *Message) DecodeHeader(b []byte) (err error) {
	s.IkeHeader, err = protocol.DecodeIkeHeader(b)
	return
}

func (s *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType) (err error) {
	if s.Payloads, err = protocol.DecodePayloads(b, nextPayload); err != nil {
		return
	}
	log.V(1).Infof("[%d]Received %s%s: payloads %s",
		s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags, *s.Payloads)
	if log.V(protocol.LOG_PACKET_JS) {
		js, _ := json.MarshalIndent(s, " ", " ")
		log.Info("Rx:\n" + string(js))
	}
	return
}

func (s *Message) Encode(tkm *Tkm, forInitiator bool) (b []byte, err error) {
	log.V(1).Infof("[%d]Sending %s%s: payloads %s",
		s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags, s.Payloads)
	if log.V(protocol.LOG_PACKET_JS) {
		js, _ := json.MarshalIndent(s, " ", " ")
		log.Info("Tx:\n" + string(js))
	}
	nextPayload := s.IkeHeader.NextPayload
	if nextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant encrypt, no tkm found")
			return
		}
		payload := protocol.EncodePayloads(s.Payloads)
		plen := len(payload) + tkm.CryptoOverhead(payload)
		// payload header
		firstPayload := protocol.PayloadTypeNone // no payloads are one possibility
		if len(s.Payloads.Array) > 0 {
			firstPayload = s.Payloads.Array[0].Type()
		}
		ph := protocol.PayloadHeader{
			NextPayload:   firstPayload,
			PayloadLength: uint16(plen),
		}.Encode()
		// prepare proper ike header
		s.IkeHeader.MsgLength = uint32(protocol.IKE_HEADER_LEN + len(ph) + plen)
		// encode ike header, and add to protocol header
		headers := append(s.IkeHeader.Encode(), ph...)
		// finally ask the tkm to apply secrets
		b, err = tkm.EncryptMac(headers, payload, forInitiator)
	} else {
		b = protocol.EncodePayloads(s.Payloads)
		s.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(s.IkeHeader.Encode(), b...)
	}
	return
}

func (msg *Message) ensurePayloads(payloadTypes []protocol.PayloadType) bool {
	mp := msg.Payloads
	for _, pt := range payloadTypes {
		if mp.Get(pt) == nil {
			return false
		}
	}
	return true
}

func (msg *Message) EnsurePayloads(payloadTypes []protocol.PayloadType) error {
	if !msg.ensurePayloads(payloadTypes) {
		return fmt.Errorf("essential payload is missing from %s message", msg.IkeHeader.ExchangeType)
	}
	return nil
}
