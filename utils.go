package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"msgbox.io/ike/crypto"
	"msgbox.io/ike/protocol"
	"msgbox.io/log"
)

func MakeSpi() (ret protocol.Spi) {
	spi, _ := rand.Prime(rand.Reader, 8*8)
	return spi.Bytes()
}

func getTransforms(pr []*protocol.SaProposal, proto protocol.ProtocolId) []*protocol.SaTransform {
	for _, p := range pr {
		if p.ProtocolId == proto {
			return p.Transforms
		}
	}
	return nil
}

func getPeerSpi(m *Message, pid protocol.ProtocolId) (peerSpi protocol.Spi, err error) {
	props := m.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload).Proposals
	for _, p := range props {
		if !p.IsSpiSizeCorrect(len(p.Spi)) {
			err = fmt.Errorf("weird spi size :%+v", *p)
			return
		}
		if p.ProtocolId == pid {
			peerSpi = p.Spi
		}
	}
	if peerSpi == nil {
		err = errors.New("Unknown Peer SPI")
		return
	}
	return
}

func DecodeMessage(dec []byte, tkm *Tkm) (*Message, error) {
	msg := &Message{}
	err := msg.DecodeHeader(dec)
	if err != nil {
		return nil, err
	}
	if len(dec) < int(msg.IkeHeader.MsgLength) {
		log.V(protocol.LOG_CODEC_ERR).Info("")
		err = protocol.ERR_INVALID_SYNTAX
		return nil, err
	}
	if err = msg.DecodePayloads(dec[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
		return nil, err
	}
	if msg.IkeHeader.NextPayload == protocol.PayloadTypeSK {
		if tkm == nil {
			err = errors.New("cant decrypt, no tkm found")
			return nil, err
		}
		b, err := tkm.VerifyDecrypt(dec)
		if err != nil {
			return nil, err
		}
		sk := msg.Payloads.Get(protocol.PayloadTypeSK)
		if err = msg.DecodePayloads(b, sk.NextPayloadType()); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func newTkmFromInit(initI *Message, ids Identities) (tkm *Tkm, err error) {
	keI := initI.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	ikeSa := initI.Payloads.Get(protocol.PayloadTypeSA).(*protocol.SaPayload)
	cs, err := crypto.NewCipherSuite(getTransforms(ikeSa.Proposals, protocol.IKE))
	if err != nil {
		return
	}
	// make sure dh tranform id is the one that was accepted
	if keI.DhTransformId != cs.DhGroup.DhTransformId {
		err = protocol.ERR_INVALID_KE_PAYLOAD
		return
	}
	tkm, err = NewTkmResponder(cs, keI.KeyData, noI.Nonce, ids) // TODO
	return
}

func authenticateI(authI *Message, initIb []byte, tkm *Tkm) bool {
	// id payload
	idI := authI.Payloads.Get(protocol.PayloadTypeIDi).(*protocol.IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Initiator ID:%s", string(idI.Data))
	// intiators's signed octet
	// initI | Nr | prf(sk_pi | IDi )
	// first part of signed bytes
	signed1 := append(initIb, tkm.Nr.Bytes()...)
	// auth payload
	authIp := authI.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	// expected auth
	auth := tkm.Auth(signed1, idI, authIp.AuthMethod, protocol.INITIATOR)
	if log.V(3) {
		// compare
		log.Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(authIp.Data))
	}
	return bytes.Equal(auth, authIp.Data)
}

func authenticateR(authR *Message, initRb []byte, tkm *Tkm) bool {
	// id payload
	idR := authR.Payloads.Get(protocol.PayloadTypeIDr).(*protocol.IdPayload)
	// id used to authenticate peer
	log.V(2).Infof("Responder ID:%s", string(idR.Data))
	// responders's signed octet
	// initR | Ni | prf(sk_pr | IDr )
	signed1 := append(initRb, tkm.Ni.Bytes()...)
	// auth payload
	authRp := authR.Payloads.Get(protocol.PayloadTypeAUTH).(*protocol.AuthPayload)
	// expected auth
	auth := tkm.Auth(signed1, idR, authRp.AuthMethod, protocol.RESPONSE)
	// compare
	if log.V(3) {
		log.Infof("auth compare \n%s vs \n%s", hex.Dump(auth), hex.Dump(authRp.Data))
	}
	return bytes.Equal(auth, authRp.Data)
}
