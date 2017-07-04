package ike

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"testing"

	"github.com/msgboxio/ike/protocol"
)

func newConfig() (config *Config) {
	config = testConfig()
	config.AddNetworkSelectors(
		&net.IPNet{IP: net.IPv4(192, 168, 10, 2).To4(), Mask: net.CIDRMask(32, 32)},
		&net.IPNet{IP: net.IPv4(10, 10, 10, 2).To4(), Mask: net.CIDRMask(32, 32)},
		true)
	return
}

var ids = PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

func TestIkeMsgGen(t *testing.T) {
	cfg := newConfig()
	cfg.LocalID = pskTestID
	cfg.PeerID = pskTestID
	sess, _ := NewInitiator(cfg, zeroAddr, zeroAddr, nil, &SessionCallback{}, logger)
	// init msg
	init := InitFromSession(sess)
	init.IkeHeader.MsgID = 42
	// encode & write init msg
	initIb, err := init.Encode(sess.tkm, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile("protocol/fuzz/corpus/corpus/sa_init_gen", initIb, 0644); err != nil {
		t.Fatal(err)
	}
	// auth
	sess.initIb = initIb
	no, _ := createNonce(sess.tkm.Ni.BitLen())
	err = sess.CreateIkeSa(&initParams{
		isInitiator:       sess.isInitiator,
		spiI:              sess.IkeSpiI,
		spiR:              sess.IkeSpiR,
		cookie:            sess.responderCookie,
		dhTransformID:     sess.tkm.suite.DhGroup.TransformId(),
		dhPublic:          sess.tkm.DhPublic,
		nonce:             no,
		rfc7427Signatures: sess.rfc7427Signatures,
	})
	if err != nil {
		t.Fatal(err)
	}
	authI, err := authFromSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	authI.IkeHeader.MsgID = 43
	// encode & write authI msg
	authIb, err := authI.Encode(sess.tkm, true, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile("protocol/fuzz/corpus/corpus/authI_gen", authIb, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCorpusDecode(t *testing.T) {
	files, err := ioutil.ReadDir("protocol/fuzz/corpus/corpus/")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := ioutil.ReadFile("protocol/fuzz/corpus/corpus/" + file.Name())
		if err != nil {
			t.Fatal(err)
		}
		t.Log("file", file.Name())
		hdr, err := protocol.DecodeIkeHeader(data)
		if err != nil {
			t.Logf("hdr: %s:%s", file.Name(), err)
			continue
		}
		plData := data[protocol.IKE_HEADER_LEN:]
		payloads, err := protocol.DecodePayloads(plData, hdr.NextPayload)
		if err != nil {
			t.Logf("pld: %s:%s", file.Name(), err)
			continue
		}
		// ensure encoding is same
		if enc := hdr.Encode(); !bytes.Equal(enc, data[:protocol.IKE_HEADER_LEN]) {
			t.Errorf("%s:%s", file.Name(), "unequal header")
		}
		if pld := protocol.EncodePayloads(payloads); !bytes.Equal(pld, plData[:len(pld)]) {
			t.Logf("%s:%s", file.Name(), "unequal payload")
		}
		msg, err := decodeMessage(data, nil, false)
		if err != nil {
			t.Logf("%s:%s", file.Name(), err)
			continue
		}
		js, err := json.MarshalIndent(msg, "", " ")
		if err != nil {
			t.Logf("%s:%s", file.Name(), err)
			continue
		}
		_ = js
		// t.Log("file", file.Name(), "data", string(js))
	}
}
