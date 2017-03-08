package ike

import (
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

type Message struct {
	IkeHeader             *protocol.IkeHeader
	Payloads              *protocol.Payloads
	LocalAddr, RemoteAddr net.Addr

	Data []byte // used to carry raw bytes
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
