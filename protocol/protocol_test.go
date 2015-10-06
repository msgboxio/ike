package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net"
	"testing"

	"math/big"

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

func testDecode(dec []byte, tkm *Tkm, t *testing.T) *Message {
	msg, err := DecodeMessage(dec, tkm)
	if err != nil {
		t.Fatal(err)
	}

	js, err := json.MarshalIndent(msg, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", string(js))

	enc, err := msg.Encode(tkm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, dec) {
		t.Errorf("comapre failed\n%s", bytediff.BashOutput.String(bytediff.Diff(dec, enc)))
	}
	return msg
}

func TestDecode(t *testing.T) {
	dec := packets.Hexit(sa_init).Bytes()

	msg := testDecode(dec, nil, t)

	shared := `327adb6c8f7185d4897b652861f5474f8e7be3882853093029d15747645cae97be69b476e0a11a12d03ea6d6ebabc51aedc7c66399b6c7d6a2e3da2b087834762e0ca23ede6a9a0a6948e8291a13969c9be0961eff40c06700c279cb99983e1f22ddba4ead1c2cd180832b534e0bfe5a2a3d4210d721efb1868b555e1912e98133c0b690abfd16e0e5d01c99c73934c380aa7c2363179069d2c8abfc061a1107e9cfa40ce3735258fcf81456bff7edc2bd63b99e2c32ff6ec33f2552b80ce870f3d268d47c72ef61c8c9e8ebe975e7012f8b79a75b2ddf914048c69b169c2f67a816c276fb1dff11fcc63e883a51505baecfb581ab375534b52d43e441996089`
	dhShared, ok := new(big.Int).SetString(shared, 16)
	if !ok {
		t.Fatal(3)
	}

	no := msg.Payloads.Get(PayloadTypeNonce).(*NoncePayload)

	transforms := []*SaTransform{
		&SaTransform{Transform: _ENCR_CAMELLIA_CBC, KeyLength: 128},
		&SaTransform{Transform: _AUTH_HMAC_SHA2_256_128},
		&SaTransform{Transform: _MODP_2048},
		&SaTransform{Transform: _PRF_HMAC_SHA2_256},
	}
	suite, _ := NewCipherSuite(transforms)
	tkm := &Tkm{
		suite:       suite,
		isInitiator: false,
		Ni:          no.Nonce,
		Nr:          no.Nonce,
		DhShared:    dhShared,
	}
	spiI, _ := hex.DecodeString("928f3f581f05a563")
	tkm.IsaCreate(spiI, []byte{})
	tkm.SetSecret([]byte("ak@msgbox.io"), []byte("foo"))

	dec = packets.Hexit(auth_psk).Bytes()
	testDecode(dec, tkm, t)
}

func TestResp(t *testing.T) {
	local, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:5000")
	udp, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}

	initI, initIb, remote, err := RxDecode(nil, udp, nil)
	if err != nil {
		t.Fatal(err)
	}
	// get ikeSa part
	ikeSa := initI.Payloads.Get(PayloadTypeSA).(*SaPayload)
	// check if we already have an sa - TODO

	tkm, err := newTkmFromInit(initI)
	if err != nil {
		t.Fatal(err)
	}

	spiI := initI.IkeHeader.SpiI
	spiR := MakeSpi()

	initR := MakeInit(spiI, spiR, ikeSa.Proposals, tkm)
	initRb, err := EncodeTx(initR, nil, udp, remote, false)
	if err != nil {
		t.Fatal(err)
	}

	tkm.IsaCreate(spiI[:], spiR[:])
	tkm.SetSecret([]byte("ak@msgbox.io"), []byte("foo"))

	authI, _, _, err := RxDecode(tkm, udp, remote)
	if err != nil {
		t.Fatal(err)
	}
	if !authenticateI(authI, initIb, tkm) {
		t.Fatal("authentication failed")
	}

	ipsecSa := authI.Payloads.Get(PayloadTypeSA).(*SaPayload)
	tsI := authI.Payloads.Get(PayloadTypeTSi).(*TrafficSelectorPayload).Selectors
	tsR := authI.Payloads.Get(PayloadTypeTSr).(*TrafficSelectorPayload).Selectors

	// responder's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	signed1 := append(initRb, tkm.Ni.Bytes()...)
	authR := MakeAuth(spiI, spiR, ipsecSa.Proposals, tsI, tsR, signed1, tkm)
	_, err = EncodeTx(authR, tkm, udp, remote, false)
	if err != nil {
		t.Fatal(err)
	}
}
