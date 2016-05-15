package ike

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func newConfig() (config *ClientCfg) {
	config = NewClientConfig()
	config.AddSelector(
		&net.IPNet{IP: net.IPv4(192, 168, 10, 2).To4(), Mask: net.CIDRMask(32, 32)},
		&net.IPNet{IP: net.IPv4(10, 10, 10, 2).To4(), Mask: net.CIDRMask(32, 32)})
	return
}

func initiatorTkm(t *testing.T) *Tkm {
	config := newConfig()
	suite, err := crypto.NewCipherSuite(config.ProposalIke.Transforms)
	if err != nil {
		t.Fatal(err)
	}
	ids := PskIdentities{
		Primary: "ak@msgbox.io",
		Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
	}
	tkm, err := NewTkmInitiator(suite, ids)
	if err != nil {
		t.Fatal(err)
	}
	// nonce for responder
	if nr, err := tkm.ncCreate(suite.PrfLen * 8); err != nil {
		t.Fatal(err)
	} else {
		tkm.Nr = nr
	}
	return tkm
}

func TestIkeMsgGen(t *testing.T) {
	cfg := newConfig()
	tkm := initiatorTkm(t)
	params := initParams{
		isInitiator:   true,
		spiI:          MakeSpi(),
		spiR:          MakeSpi(),
		proposals:     []*protocol.SaProposal{cfg.ProposalIke},
		nonce:         tkm.Ni,
		dhTransformId: tkm.suite.DhGroup.DhTransformId,
		dhPublic:      tkm.DhPublic,
	}
	// init msg
	init := makeInit(params)
	init.IkeHeader.MsgId = 42
	// encode & write init msg
	initIb, err := init.Encode(tkm)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile("protocol/fuzz/corpus/corpus/sa_init_gen", initIb, 0644); err != nil {
		t.Fatal(err)
	}

	// auth
	signed1 := append(initIb, tkm.Nr.Bytes()...)
	authI := makeAuth(params.spiI,
		params.spiR,
		[]*protocol.SaProposal{cfg.ProposalEsp},
		cfg.TsI,
		cfg.TsR, signed1,
		tkm,
		cfg.IsTransportMode)
	// overwrite NextPayload
	authI.IkeHeader.NextPayload = protocol.PayloadTypeIDi
	authI.IkeHeader.MsgId = 43
	// encode & write authI msg
	authIb, err := authI.Encode(tkm)
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
		//
		// hdr, err := protocol.DecodeIkeHeader(data)
		// if err != nil {
		// 	t.Errorf("hdr: %s:%s", file.Name(), err)
		// 	t.Fail()
		// }
		// plData := data[protocol.IKE_HEADER_LEN:]
		// payloads, err := protocol.DecodePayloads(plData, hdr.NextPayload)
		// if err != nil {
		// 	t.Errorf("pld: %s:%s", file.Name(), err)
		// 	t.Fail()
		// }
		// // ensure encoding is same
		// if enc := hdr.Encode(); !bytes.Equal(enc, data[:protocol.IKE_HEADER_LEN]) {
		// 	t.Errorf("%s:%s", file.Name(), "unequal header")
		// 	t.Fail()
		// }
		// if pld := protocol.EncodePayloads(payloads); !bytes.Equal(pld, plData[:len(pld)]) {
		// 	t.Errorf("%s:%s", file.Name(), "unequal payload")
		// 	t.Fail()
		// }

		fmt.Println(file.Name())
		msg, err := decodeMessage(data, nil)
		if err != nil {
			t.Errorf("%s:%s", file.Name(), err)
			t.Fail()
		}
		js, err := json.MarshalIndent(msg, "", " ")
		if err != nil {
			t.Errorf("%s:%s", file.Name(), err)
			t.Fail()
		}
		t.Logf("%s: \n%s", file.Name(), string(js))
	}
}
