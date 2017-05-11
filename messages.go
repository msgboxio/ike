package ike

import (
	"fmt"
	"io"
	stdlog "log"
	"net"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// Message carries the ike packet
type Message struct {
	IkeHeader             *protocol.IkeHeader
	Payloads              *protocol.Payloads
	LocalAddr, RemoteAddr net.Addr

	Data []byte // used to carry raw bytes
}

// DecodeHeader decodes the ike header and replaces the IkeHeader member
func (msg *Message) DecodeHeader(b []byte) (err error) {
	msg.IkeHeader, err = protocol.DecodeIkeHeader(b)
	return
}

// DecodePayloads decodes & replaces the payloads member with list of decoded payloads
func (msg *Message) DecodePayloads(b []byte, nextPayload protocol.PayloadType, log log.Logger) (err error) {
	if msg.Payloads, err = protocol.DecodePayloads(b, nextPayload); err != nil {
		return
	}
	if protocol.PacketLog {
		stdlog.Println("rx:" + spew.Sprintf("%#v", msg))
	}
	log.Log("rx", fmt.Sprintf("[%d] %s%s", msg.IkeHeader.MsgID, msg.IkeHeader.ExchangeType, msg.IkeHeader.Flags),
		"payloads", *msg.Payloads)
	return
}

// DecodeMessage decodes an keeps the message buffer for later decryption
func DecodeMessage(b []byte, log log.Logger) (msg *Message, err error) {
	msg = &Message{}
	if err = msg.DecodeHeader(b); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = io.ErrShortBuffer
		return
	}
	// further decode
	pld := b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength]
	if err = msg.DecodePayloads(pld, msg.IkeHeader.NextPayload, log); err != nil {
		return
	}
	// save for later
	msg.Data = b
	return
}

// DecryptMessage uses crypto keys to decode & verify the message
func DecryptMessage(msg *Message, tkm *Tkm, forInitiator bool, log log.Logger) (err error) {
	if msg.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		var b []byte
		if b, err = tkm.VerifyDecrypt(msg.Data, forInitiator); err != nil {
			return err
		}
		sk := msg.Payloads.Get(protocol.PayloadTypeSK)
		if err = msg.DecodePayloads(b, sk.NextPayloadType(), log); err != nil {
			return err
		}
	}
	return
}

// EnsurePayloads checks if the needed payloads are present in the message
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

// CheckFlags checks if flags are correctly set for us
// NOTE: To simply implementation, we do not handle the case
// where original responder starts transactions. In reality this only effects CHILD_SA txns
// so this function is not to be used for NOTIFICATIONS
func (msg *Message) CheckFlags() error {
	flags := msg.IkeHeader.Flags
	// check flags
	if flags.IsInitiator() {
		if flags.IsResponse() {
			return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID, "initiator sent a response")
		}
	} else if !flags.IsResponse() {
		return errors.Wrap(protocol.ERR_INVALID_MESSAGE_ID, "responder sent a request")
	}
	return nil
}

// Encode encodes the message using crypto keys
func (msg *Message) Encode(tkm *Tkm, forInitiator bool, log log.Logger) (b []byte, err error) {
	if protocol.PacketLog {
		stdlog.Println("tx:" + spew.Sprintf("%#v", msg))
	}
	log.Log("tx", fmt.Sprintf("[%d] %s%s", msg.IkeHeader.MsgID, msg.IkeHeader.ExchangeType, msg.IkeHeader.Flags),
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
		payload := protocol.EncodePayloads(msg.Payloads)
		plen := len(payload) + tkm.CryptoOverhead(payload)
		// sk payload header
		skHdr := protocol.PayloadHeader{
			NextPayload:   firstPayloadType,
			PayloadLength: uint16(plen),
		}.Encode()
		// prepare proper ike header
		msg.IkeHeader.MsgLength = uint32(protocol.IKE_HEADER_LEN + len(skHdr) + plen)
		// finally ask the tkm to apply secrets
		b, err = tkm.EncryptMac(append(append(msg.IkeHeader.Encode(), skHdr...), payload...), forInitiator)
	} else {
		b = protocol.EncodePayloads(msg.Payloads)
		msg.IkeHeader.NextPayload = firstPayloadType
		msg.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN)
		b = append(msg.IkeHeader.Encode(), b...)
	}
	return
}
