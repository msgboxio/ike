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
92 8f 3f 58 1f 05 a5 63  00 00 00 00 00 00 00 00
21 20 22 08 00 00 00 00  00 00 01 a8 22 00 00 60
02 00 00 34 01 01 08 04  92 8f 3f 58 1f 05 a5 63
03 00 00 0c 01 00 00 17  80 0e 01 00 03 00 00 08
02 00 00 05 03 00 00 08  03 00 00 0c 00 00 00 08
04 00 00 0e 00 00 00 28  02 03 04 03 13 5a a9 69
03 00 00 0c 01 00 00 17  80 0e 01 00 03 00 00 08
05 00 00 01 00 00 00 08  03 00 00 0c 28 00 01 08
00 0e 00 00 ed cf 56 38  1a 58 71 62 48 fc b5 89
0d f2 08 19 91 af f3 16  39 1c 2f 16 80 ef 88 49
21 76 38 40 98 4d 44 73  71 ed 59 05 35 44 90 a0
2f ef f0 5a 0e 99 c9 e6  f0 06 d4 c2 e3 03 ab 62
01 7f 5b 34 94 ca 7d 30  7e 41 9a b2 96 21 e1 68
e3 da f1 66 4e 88 13 14  8f b0 9e a3 88 d7 7d 92
28 11 8e 47 67 d4 e5 f4  80 ce 22 ae 1f 70 c3 b0
eb 59 e5 c7 26 0d f9 69  81 96 e9 81 17 7a a2 55
2b a6 40 f0 cd 12 34 16  7b 9a ac 3d ca b2 07 39
cf cc 95 17 28 6b 79 5d  6b d5 03 36 50 a6 15 18
81 ae 8c d8 8d ec 42 5d  40 e2 96 0d d9 fe c0 3c
ef 8b 2e 3f 41 50 66 ad  00 bf df 6c 22 e4 1c b6
ad 2e 4f c7 7d 89 10 8d  b4 25 23 6e a9 b7 d7 d8
40 9a 53 04 31 33 c1 87  25 5c c0 fb 40 86 10 a9
f2 c2 98 98 2b fd 26 87  4c 57 b5 1f 38 dc 7f fc
6b f8 a4 cb 91 33 45 aa  aa a8 33 ff b9 33 51 aa
b6 7a f6 83 00 00 00 24  63 a0 2b 62 47 56 80 de
1c 50 af 97 a8 2a 7a bd  8d 46 4d 95 11 f8 7a c8
6a 3e 1e 42 17 40 5a fa                         
`
var auth_psk = `
92 8f 3f 58 1f 05 a5 63  00 00 00 00 00 00 00 00
2e 20 23 08 00 00 00 01  00 00 00 e0 23 00 00 c4
fc bb 4a 7a 26 d6 a6 6d  41 d3 72 ec d4 cf ae f3
c2 45 44 34 a1 d9 67 04  2f 87 ce f5 0e a8 b8 16
d4 55 a5 5a 7a 63 44 85  46 62 f6 3e 51 4b 06 73
c8 a4 af f7 06 d3 2a 11  11 7f 08 20 50 c8 ca ed
cc 31 b4 da d6 96 66 f4  53 55 45 17 32 d7 11 3a
6c d1 9a f9 2e f9 0f dc  44 c8 4e c7 c1 68 4f 1d
03 a2 ef 97 66 8b 80 73  3f a9 78 31 96 92 e7 26
cf 72 57 fc 6c bf d6 9a  c9 f8 41 14 2d 05 11 1b
b5 84 e6 5f 08 25 82 37  59 10 ca 0b c2 59 8a 65
8c 9e 47 4a 9f 25 f0 ae  e9 18 41 0b 6e ad d0 4f
c3 5f a1 23 9f 85 45 6a  ba 42 47 1e 37 d0 22 05
e2 51 6a e1 95 b6 72 60  a0 a3 41 27 ed 3c 59 d6
`

func init() {
	flag.Set("logtostderr", "true")
	flag.Set("v", "4")
	flag.Parse()
}

var env map[Spi]*Tkm

func testDecode(dec []byte, t *testing.T) *Message {
	msg := &Message{}
	err := msg.DecodeHeader(dec)
	if err != nil {
		t.Fatal(err)
	}

	tkm := env[msg.IkeHeader.SpiI]

	if err = msg.DecodePayloads(dec, tkm); err != nil {
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
	return msg
}

func testDecodeInit(dec []byte, t *testing.T) *Message {
	msg := testDecode(dec, t)
	ke := msg.Payloads[PayloadTypeKE].(*KePayload)
	no := msg.Payloads[PayloadTypeNonce].(*NoncePayload)
	tkm, err := InitTkmResponder(ke.DhTransformId, ke.KeyData, no.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	env[msg.IkeHeader.SpiI] = tkm
	return msg

}
func TestDecode(t *testing.T) {
	env = make(map[Spi]*Tkm)
	dec := packets.Hexit(sa_init).Bytes()
	testDecodeInit(dec, t)
	// for _, v := range env {
	// 	js, _ := json.Marshal(v)
	// 	t.Logf("Tkm: %s", js)
	// }
	dec = packets.Hexit(auth_psk).Bytes()
	testDecode(dec, t)
}

func TestRxTx(t *testing.T) {
	env = make(map[Spi]*Tkm)
	local, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:5000")
	udp, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1500)
	n, from, err := udp.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d from %s:\n%s", n, from, hex.Dump(b[:n]))
	init := testDecodeInit(b[:n], t)

	js, err := json.MarshalIndent(init, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("INIT: \n%s", string(js))

	n, err = udp.WriteToUDP(b[:n], from)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d to %s", n, from)

	n, from, err = udp.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d from %s:\n%s", n, from, hex.Dump(b[:n]))

	auth := testDecode(b[:n], t)
	js, err = json.MarshalIndent(auth, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("AUTH: \n%s", string(js))

}
