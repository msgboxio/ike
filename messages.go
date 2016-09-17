package ike

import (
	"encoding/json"
	"errors"
	"fmt"
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
)

type Message struct {
	IkeHeader         *protocol.IkeHeader
	Payloads          *protocol.Payloads
	Data              []byte // used to carry raw bytes
	LocalIp, RemoteIp net.IP
}

func (s *Message) DecodeHeader(b []byte) (err error) {
	s.IkeHeader, err = protocol.DecodeIkeHeader(b)
	return
}

func (s *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType) (err error) {
	if s.Payloads, err = protocol.DecodePayloads(b, nextPayload); err != nil {
		return
	}
	log.V(1).Infof("Received %s: payloads %s", s.IkeHeader.ExchangeType, *s.Payloads)
	if log.V(protocol.LOG_PACKET_JS) {
		js, _ := json.MarshalIndent(s, " ", " ")
		log.Info("Rx:\n" + string(js))
	}
	return
}

func (s *Message) Encode(tkm *Tkm) (b []byte, err error) {
	log.V(1).Infof("Sending %s: payloads %s", s.IkeHeader.ExchangeType, s.Payloads)
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
		b, err = tkm.EncryptMac(s)
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
