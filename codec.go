package ike

import (
	"io"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

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

func DecryptMessage(m *Message, tkm *Tkm, forInitiator bool, log *logrus.Logger) (err error) {
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

func EncodeMessage(msg *Message, tkm *Tkm, forInitiator bool, log *logrus.Logger) (b []byte, err error) {
	if log.Level == logrus.DebugLevel {
		log.Debug("Tx:\n" + spew.Sdump(msg))
	} else {
		log.Infof("[%d]Sending %s%s: payloads %s",
			msg.IkeHeader.MsgId, msg.IkeHeader.ExchangeType, msg.IkeHeader.Flags, msg.Payloads)
	}
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
