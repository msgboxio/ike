// +build gofuzz

package fuzz

import (
	"bytes"

	"github.com/msgboxio/ike/protocol"
)

func Fuzz(data []byte) int {
	hdr, err := protocol.DecodeIkeHeader(data)
	if err != nil {
		return 0
	}
	plData := data[protocol.IKE_HEADER_LEN:]
	payloads, err := protocol.DecodePayloads(plData, hdr.NextPayload)
	if err != nil {
		return 0
	}

	// ensure encoding is same
	if enc := hdr.Encode(); !bytes.Equal(enc, data[:protocol.IKE_HEADER_LEN]) {
		panic("unequal header")
	}
	if pld := protocol.EncodePayloads(payloads); !bytes.Equal(pld, plData[:len(pld)]) {
		panic("unequal payload")
	}
	return 1
}
