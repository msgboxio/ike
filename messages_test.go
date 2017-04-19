package ike

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/gopacket/bytediff"
	"github.com/msgboxio/ike/protocol"
)

func decodeMessage(dec []byte, tkm *Tkm, forInitiator bool) (*Message, error) {
	msg := &Message{}
	err := msg.DecodeHeader(dec)
	if err != nil {
		return nil, err
	}
	if len(dec) < int(msg.IkeHeader.MsgLength) {
		err = protocol.ERR_INVALID_SYNTAX
		return nil, err
	}
	if err = msg.DecodePayloads(dec[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload, logger); err != nil {
		return nil, err
	}
	if msg.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant decrypt, no tkm found")
			return nil, err
		}
		b, err := tkm.VerifyDecrypt(dec, forInitiator)
		if err != nil {
			return nil, err
		}
		sk := msg.Payloads.Get(protocol.PayloadTypeSK)
		if err = msg.DecodePayloads(b, sk.NextPayloadType(), logger); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func testDecode(dec []byte, tkm *Tkm, forInitiator bool, t *testing.T) *Message {
	msg, err := decodeMessage(dec, tkm, forInitiator)
	if err != nil {
		t.Fatal(err)
	}

	js, err := json.MarshalIndent(msg, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", string(js))

	enc, err := msg.Encode(tkm, forInitiator, logger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, dec) {
		t.Errorf("comapre failed\n%s", bytediff.BashOutput.String(bytediff.Diff(dec, enc)))
	}
	return msg
}
