package ike

import (
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
	level.Debug(log).Log("Rx:\n" + spew.Sdump(s))
	log.Log("[%d]Received %s%s: payloads %s",
		s.IkeHeader.MsgId, s.IkeHeader.ExchangeType, s.IkeHeader.Flags, *s.Payloads)
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
