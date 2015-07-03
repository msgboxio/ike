package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"msgbox.io/log"
)

func MakeSpi() (ret Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	copy(ret[:], spi.Bytes())
	return
}

var (
	InitPayloads = []PayloadType{PayloadTypeSA, PayloadTypeKE, PayloadTypeNonce}

	AuthIPayloads = []PayloadType{PayloadTypeIDi, PayloadTypeAUTH, PayloadTypeSA, PayloadTypeTSi, PayloadTypeTSr}
	AuthRPayloads = []PayloadType{PayloadTypeIDr, PayloadTypeAUTH, PayloadTypeSA, PayloadTypeTSi, PayloadTypeTSr}

	AuthPayloads = []PayloadType{PayloadTypeIDr, PayloadTypeAUTH}
)

func EnsurePayloads(msg *Message, payloadTypes []PayloadType) bool {
	mp := msg.Payloads
	for _, pt := range payloadTypes {
		if mp.Get(pt) == nil {
			return false
		}
	}
	return true
}

func getTransforms(pr []*SaProposal, proto ProtocolId) []*SaTransform {
	for _, p := range pr {
		if p.ProtocolId == proto {
			return p.Transforms
		}
	}
	return nil
}

func readPacket(udp *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	b := make([]byte, 1500)
	n, from, err := udp.ReadFromUDP(b)
	if err != nil {
		return nil, nil, err
	}
	b = b[:n]
	log.Infof("%d from %s", n, from)
	log.V(4).Info("\n" + hex.Dump(b))
	return b, from, nil
}

func RxDecode(tkm *Tkm, udp *net.UDPConn, remote *net.UDPAddr) (*Message, []byte, *net.UDPAddr, error) {
	b, from, err := readPacket(udp)
	if err != nil {
		return nil, nil, from, err
	}
	if remote != nil && remote.String() != from.String() {
		return nil, nil, from, fmt.Errorf("from different address: %s", from)
	}
	msg, err := DecodeMessage(b, tkm)
	if err != nil {
		return nil, nil, from, err
	}
	if log.V(3) {
		js, _ := json.MarshalIndent(msg, " ", " ")
		log.Info("\n" + string(js))
	}
	return msg, b, from, nil
}

func EncodeTx(msg *Message, tkm *Tkm, udp *net.UDPConn, remote *net.UDPAddr, isConnected bool) (msgB []byte, err error) {
	if msgB, err = msg.Encode(tkm); err != nil {
		return
	} else {
		var n int
		if isConnected {
			n, err = udp.Write(msgB)
		} else {
			n, err = udp.WriteToUDP(msgB, remote)
		}
		if err != nil {
			return
		} else {
			log.Infof("%d to %s", n, remote)
			log.V(4).Info("\n" + hex.Dump(msgB))
			if log.V(3) {
				js, _ := json.MarshalIndent(msg, " ", " ")
				log.Info("\n" + string(js))
			}
		}
		return msgB, nil
	}
}

func newTkmFromInit(initI *Message) (tkm *Tkm, err error) {
	keI := initI.Payloads.Get(PayloadTypeKE).(*KePayload)
	noI := initI.Payloads.Get(PayloadTypeNonce).(*NoncePayload)
	ikeSa := initI.Payloads.Get(PayloadTypeSA).(*SaPayload)
	cs := NewCipherSuite(getTransforms(ikeSa.Proposals, IKE))
	if cs == nil {
		err = errors.New("no appropriate ciphersuite")
		return
	}
	// make sure dh tranform id is the one that was accepted
	if keI.DhTransformId != cs.dhGroup.DhTransformId {
		err = ERR_INVALID_KE_PAYLOAD
		return
	}
	tkm, err = NewTkmResponder(cs, keI.KeyData, noI.Nonce)
	return
}

func authenticateI(authI *Message, initIb []byte, tkm *Tkm) bool {
	// intiators's signed octet
	// initI | Nr | prf(sk_pi | IDi )
	idI := authI.Payloads.Get(PayloadTypeIDi).(*IdPayload)
	log.V(2).Infof("ID:%s", string(idI.Data))
	auth := tkm.Auth(append(initIb, tkm.Nr.Bytes()...), idI.Encode(), INITIATOR)
	_authI := authI.Payloads.Get(PayloadTypeAUTH).(*AuthPayload)
	log.V(3).Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(_authI.Data))
	return bytes.Equal(auth, _authI.Data)
}

func authenticateR(authR *Message, initRb []byte, tkm *Tkm) bool {
	// responders's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	idR := authR.Payloads.Get(PayloadTypeIDr).(*IdPayload)
	log.V(2).Infof("ID:%s", string(idR.Data))
	auth := tkm.Auth(append(initRb, tkm.Ni.Bytes()...), idR.Encode(), RESPONSE)
	_authR := authR.Payloads.Get(PayloadTypeAUTH).(*AuthPayload)
	log.V(3).Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(_authR.Data))
	return bytes.Equal(auth, _authR.Data)
}
