package ike

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net"
	"testing"

	"msgbox.io/packets"

	"code.google.com/p/gopacket/bytediff"
)

var sa_init = `
bb 64 cb a7 c6 8f 30 31  00 00 00 00 00 00 00 00
21 20 22 08 00 00 00 00  00 00 01 a8 22 00 00 60
02 00 00 34 01 01 08 04  bb 64 cb a7 c6 8f 30 31
03 00 00 0c 01 00 00 17  80 0e 01 00 03 00 00 08
02 00 00 05 03 00 00 08  03 00 00 0c 00 00 00 08
04 00 00 0e 00 00 00 28  02 03 04 03 f6 8d b8 0e
03 00 00 0c 01 00 00 17  80 0e 01 00 03 00 00 08
05 00 00 01 00 00 00 08  03 00 00 0c 28 00 01 08
00 0e 00 00 72 71 77 c9  42 dc 78 93 c0 af 67 c4
33 0d a4 f2 f7 ca 07 cf  5f 47 a2 1a 4f ec 1b 3a
84 f5 0a 8a e2 43 aa 63  c1 7a 4b 15 f9 2d 15 a6
81 5c 29 dd a9 2e a1 b0  0b 0c 36 ed 71 17 10 2f
8a 83 8c bc 3c 66 bd cb  d3 cc 91 5f 64 e8 be 8c
41 a6 4a 9b 99 31 a7 cf  dd a8 47 39 61 18 2c cf
2b 7e 3b e2 31 93 96 84  4d 4c b9 67 34 32 c1 ff
72 2f 1e 97 aa 8a 5f 62  53 51 2d 9b d5 c5 ce 36
ca 1a 89 6a 6a 6f 84 cd  8e bb 9d 2d 32 c8 e6 5c
75 21 6e 74 87 f4 e2 5c  02 81 f7 31 6a 68 e9 45
e6 70 1c a2 78 a1 02 97  c8 10 31 3a e9 ba 79 d0
64 4a a3 e6 22 f8 dc a8  41 3d 8a e8 40 47 7c 89
07 f1 f0 6a a0 d0 e4 be  d6 3a b6 c9 13 bd 36 ef
c4 6d 91 3c 72 54 94 8f  24 a7 2c 27 8b 5d 42 95
e9 e1 9e 6d bd db 50 ad  94 2e 3f 4a 78 ae eb 7c
7e 60 a1 df ca c7 a6 4d  5c 25 fa 21 8d 8c 8b 37
5f 7e 14 6c 00 00 00 24  56 3c 79 96 67 1f 86 bd
ce f4 c1 44 11 b4 27 d4  91 8c ba 47 64 98 35 96
33 5d 91 e4 3d af 52 87                         
`

func init() {
	flag.Set("logtostderr", "true")
	flag.Set("v", "4")
	flag.Parse()
}

func TestDecodeInit(t *testing.T) {
	msg := &Message{}
	dec := packets.Hexit(sa_init).Bytes()
	err := msg.Decode(dec)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.MarshalIndent(msg, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", string(js))

	enc := msg.Encode()
	if !bytes.Equal(enc, dec) {
		t.Errorf("comapre failed\n%s", bytediff.BashOutput.String(bytediff.Diff(dec, enc)))
	}

	ke := msg.Payloads[PayloadTypeKE].(*KePayload)
	tkm, err := InitTkm(ke.DhTransformId, 32)
	if err != nil {
		t.Fatal(err)
	}
	no := msg.Payloads[PayloadTypeNonce].(*NoncePayload)
	tkm.NonceO = no.Nonce
	err = tkm.DhGenerateKey(ke.KeyData)
	if err != nil {
		t.Fatal(err)
	}
	// SKEYSEED = prf(new(big.Int).Add(tkm.Nonce, tkm.NonceO), tkm.dhShared)

}

func testRx(t *testing.T) {
	local, _ := net.ResolveUDPAddr("udp", "0.0.0.0:5000")
	udp, err := net.ListenUDP("udp", local)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1500)
	n, from, err := udp.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d from %s:\n%s", n, from, hex.Dump(b[:n]))
	msg := &Message{}

	if err = msg.Decode(b[:n]); err != nil {
		t.Fatal(err)
	}
	js, err := json.MarshalIndent(msg, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("INIT: \n%s", string(js))
}
