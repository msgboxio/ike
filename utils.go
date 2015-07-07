package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"msgbox.io/log"
)

func MakeSpi() (ret Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	return spi.Bytes()
}

var (
	InitPayloads = []PayloadType{PayloadTypeSA, PayloadTypeKE, PayloadTypeNonce}

	AuthIPayloads = []PayloadType{PayloadTypeIDi, PayloadTypeAUTH, PayloadTypeSA, PayloadTypeTSi, PayloadTypeTSr}
	AuthRPayloads = []PayloadType{PayloadTypeIDr, PayloadTypeAUTH, PayloadTypeSA, PayloadTypeTSi, PayloadTypeTSr}
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

func ReadPacket(conn net.Conn, remote net.Addr, isConnected bool) (b []byte, from net.Addr, err error) {
	b = make([]byte, 1500)
	n := 0
	if isConnected {
		n, err = conn.Read(b)
		from = remote
	} else {
		udp := conn.(*net.UDPConn)
		n, from, err = udp.ReadFromUDP(b)
	}
	if err != nil {
		return nil, nil, err
	}
	b = b[:n]
	log.Infof("%d from %s", n, from)
	log.V(4).Info("\n" + hex.Dump(b))
	return b, from, nil
}

func DecodeMessage(dec []byte, tkm *Tkm) (*Message, error) {
	msg := &Message{}
	err := msg.DecodeHeader(dec)
	if err != nil {
		return nil, err
	}
	if len(dec) < int(msg.IkeHeader.MsgLength) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return nil, err
	}
	msg.Payloads = MakePayloads()
	if err = msg.DecodePayloads(dec[IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
		return nil, err
	}
	if msg.IkeHeader.NextPayload == PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant decrypt, no tkm found")
			return nil, err
		}
		b, err := tkm.VerifyDecrypt(dec)
		if err != nil {
			return nil, err
		}
		sk := msg.Payloads.Get(PayloadTypeSK)
		if err = msg.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func RxDecode(tkm *Tkm, udp *net.UDPConn, remote *net.UDPAddr) (*Message, []byte, *net.UDPAddr, error) {
	b, fr, err := ReadPacket(udp, remote, false)
	if err != nil {
		return nil, nil, nil, err
	}
	from := fr.(*net.UDPAddr)
	if remote != nil && remote.String() != from.String() {
		return nil, nil, from, fmt.Errorf("from different address: %s", from)
	}
	msg, err := DecodeMessage(b, tkm)
	if err != nil {
		return nil, nil, from, err
	}
	return msg, b, from, nil
}

func EncodeTx(msg *Message, tkm *Tkm, conn net.Conn, remote net.Addr, isConnected bool) (msgB []byte, err error) {
	if msgB, err = msg.Encode(tkm); err != nil {
		return
	} else {
		var n int
		if isConnected {
			n, err = conn.Write(msgB)
		} else {
			udp := conn.(*net.UDPConn)
			addr := remote.(*net.UDPAddr)
			n, err = udp.WriteToUDP(msgB, addr)
		}
		if err != nil {
			return
		} else {
			log.Infof("%d to %s", n, remote)
			log.V(4).Info("\n" + hex.Dump(msgB))
		}
		return msgB, nil
	}
}

func newTkmFromInit(initI *Message, ids Identities) (tkm *Tkm, err error) {
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
	tkm, err = NewTkmResponder(cs, keI.KeyData, noI.Nonce, ids) // TODO
	return
}

func authenticateI(authI *Message, initIb []byte, tkm *Tkm) bool {
	// id payload
	idI := authI.Payloads.Get(PayloadTypeIDi).(*IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Initiator ID:%s", string(idI.Data))
	// intiators's signed octet
	// initI | Nr | prf(sk_pi | IDi )
	// first part of signed bytes
	signed1 := append(initIb, tkm.Nr.Bytes()...)
	// auth payload
	authIp := authI.Payloads.Get(PayloadTypeAUTH).(*AuthPayload)
	// expected auth
	auth := tkm.Auth(signed1, idI, authIp.AuthMethod, INITIATOR)
	// compare
	log.V(3).Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(authIp.Data))
	return bytes.Equal(auth, authIp.Data)
}

func authenticateR(authR *Message, initRb []byte, tkm *Tkm) bool {
	// id payload
	idR := authR.Payloads.Get(PayloadTypeIDr).(*IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Responder ID:%s", string(idR.Data))
	// responders's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	signed1 := append(initRb, tkm.Ni.Bytes()...)
	// auth payload
	authRp := authR.Payloads.Get(PayloadTypeAUTH).(*AuthPayload)
	// expected auth
	auth := tkm.Auth(signed1, idR, authRp.AuthMethod, RESPONSE)
	// compare
	log.V(3).Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(authRp.Data))
	return bytes.Equal(auth, authRp.Data)
}
