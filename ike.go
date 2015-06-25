package ike

import (
	"encoding/hex"
	"errors"
	"net"

	"math/big"

	"msgbox.io/log"
	"msgbox.io/packets"
)

const (
	IKE_PORT      = 500
	IKE_NATT_PORT = 4500
)

// mimimal impl

// IKE_SA_INIT
// generate SKEYSEED, IKE sa is encrypted

// IKE_AUTH
// to create IKE SA and the first child SA.
// authenticate peer & create child SA

// understand CREATE_CHILD_SA request so it can
// reply with CREATE_CHILD_SA error response saying NO_ADDITIONAL_SAS

// understand INFORMATIONAL request
// so it can reply with empty INFORMATIONAL response

// dont keep message ids, only 1 & 2
// dont need to protect against replay attacks

const (
	LOG_CODEC = 3
)

type Packet interface {
	Decode([]byte) error
	Encode() []byte
}

const (
	IKEV2_MAJOR_VERSION = 2
	IKEV2_MINOR_VERSION = 0
)

type Spi [8]byte

type PayloadType uint8

const (
	PayloadTypeNone    PayloadType = 0  // No Next Payload
	PayloadTypeSA      PayloadType = 33 // Security Association
	PayloadTypeKE      PayloadType = 34 // Key Exchange
	PayloadTypeIDi     PayloadType = 35 // Identification - Initiator
	PayloadTypeIDr     PayloadType = 36 // Identification - Responder
	PayloadTypeCERT    PayloadType = 37 // Certificate
	PayloadTypeCERTREQ PayloadType = 38 // Certificate Request
	PayloadTypeAUTH    PayloadType = 39 // Authentication
	// PayloadTypeNi      PayloadType = 40 // Nonce
	// PayloadTypeNr      PayloadType = 40 // Nonce
	PayloadTypeNonce PayloadType = 40 // Nonce
	PayloadTypeN     PayloadType = 41 // Notify
	PayloadTypeD     PayloadType = 42 // Delete
	PayloadTypeV     PayloadType = 43 // Vendor ID
	PayloadTypeTSi   PayloadType = 44 // Traffic Selector - Initiator
	PayloadTypeTSr   PayloadType = 45 // Traffic Selector - Responder
	PayloadTypeSK    PayloadType = 46 // Encrypted and Authenticated
	PayloadTypeCP    PayloadType = 47 // Configuration
	PayloadTypeEAP   PayloadType = 48 // Extensible Authentication
)

type IkeExchangeType uint16

const (
	IKE_SA_INIT     IkeExchangeType = 34
	IKE_AUTH        IkeExchangeType = 35
	CREATE_CHILD_SA IkeExchangeType = 36
	INFORMATIONAL   IkeExchangeType = 37
)

type IkeFlags uint8

const (
	RESPONSE  IkeFlags = 1 << 5
	VERSION   IkeFlags = 1 << 4
	INITIATOR IkeFlags = 1 << 3
)

func (f IkeFlags) IsResponse() bool {
	if f&RESPONSE != 0 {
		return true
	}
	return false
}
func (f IkeFlags) IsInitiator() bool {
	if f&INITIATOR != 0 {
		return true
	}
	return false
}

type ProtocolId uint8

const (
	NoProtocol ProtocolId = 1
	IKE        ProtocolId = 1
	AH         ProtocolId = 2
	ESP        ProtocolId = 3
)

type TransformType uint8

const (
	TRANSFORM_TYPE_ENCR  TransformType = 1 //  Encryption Algorithm  used in IKE and ESP
	TRANSFORM_TYPE_PRF   TransformType = 2 //  Pseudorandom Function used in IKE
	TRANSFORM_TYPE_INTEG TransformType = 3 //   Integrity Algorithm  used in   IKE*, AH, optional in ESP
	TRANSFORM_TYPE_DH    TransformType = 4 //Diffie-Hellman Group used in   IKE, optional in AH & ESP
	TRANSFORM_TYPE_ESN   TransformType = 5 // Extended Sequence Numbers used in AH and ESP
)

type EncrTransformId uint16

const (
	ENCR_DES_IV64 EncrTransformId = 1  // (UNSPECIFIED)
	ENCR_DES      EncrTransformId = 2  // [RFC2405], [DES]
	ENCR_3DES     EncrTransformId = 3  // [RFC2451]
	ENCR_RC5      EncrTransformId = 4  // [RFC2451]
	ENCR_IDEA     EncrTransformId = 5  // [RFC2451], [IDEA]
	ENCR_CAST     EncrTransformId = 6  // [RFC2451]
	ENCR_BLOWFISH EncrTransformId = 7  // [RFC2451]
	ENCR_3IDEA    EncrTransformId = 8  // (UNSPECIFIED)
	ENCR_DES_IV32 EncrTransformId = 9  // (UNSPECIFIED)
	ENCR_NULL     EncrTransformId = 11 // [RFC2410]
	ENCR_AES_CBC  EncrTransformId = 12 // [RFC3602]
	ENCR_AES_CTR  EncrTransformId = 13 // [RFC3686]
)

type PrfTransformId uint16

const (
	PRF_HMAC_MD5   PrfTransformId = 1 // [RFC2104], [MD5]
	PRF_HMAC_SHA1  PrfTransformId = 2 // [RFC2104], [FIPS.180-4.2012]
	PRF_HMAC_TIGER PrfTransformId = 3 // (UNSPECIFIED)
)

type AuthTransformId uint16

const (
	AUTH_NONE         AuthTransformId = 0 //
	AUTH_HMAC_MD5_96  AuthTransformId = 1 // [RFC2403]
	AUTH_HMAC_SHA1_96 AuthTransformId = 2 // [RFC2404]
	AUTH_DES_MAC      AuthTransformId = 3 // (UNSPECIFIED)
	AUTH_KPDK_MD5     AuthTransformId = 4 // (UNSPECIFIED)
	AUTH_AES_XCBC_96  AuthTransformId = 5 // [RFC3566]
)

type DhTransformId uint16

const (
	MODP_NONE DhTransformId = 0  //
	MODP_768  DhTransformId = 1  // Appendix B
	MODP_1024 DhTransformId = 2  // Appendix B
	MODP_1536 DhTransformId = 5  // [ADDGROUP]
	MODP_2048 DhTransformId = 14 // [ADDGROUP]
	MODP_3072 DhTransformId = 15 // [ADDGROUP]
	MODP_4096 DhTransformId = 16 // [ADDGROUP]
	MODP_6144 DhTransformId = 17 // [ADDGROUP]
	MODP_8192 DhTransformId = 18 // [ADDGROUP]
)

type EsnTransformid uint16

const (
	ESN_NONE EsnTransformid = 0
	ESN      EsnTransformid = 1
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Initiator's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Responder's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Message ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Length                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
const (
	IKE_HEADER_LEN = 28
)

type IkeHeader struct {
	SpiI, SpiR                 Spi
	NextPayload                PayloadType
	MajorVersion, MinorVersion uint8 // 4 bits
	ExchangeType               IkeExchangeType
	Flags                      IkeFlags
	MsgId                      uint32
	MsgLength                  uint32
}

func DecodeIkeHeader(b []byte) (h *IkeHeader, err error) {
	h = &IkeHeader{}
	if len(b) < IKE_HEADER_LEN {
		log.V(LOG_CODEC).Infof("Packet Too short : %d", len(b))
		return nil, ERR_INVALID_SYNTAX
	}
	copy(h.SpiI[:], b)
	copy(h.SpiR[:], b[8:])
	pt, _ := packets.ReadB8(b, 16)
	h.NextPayload = PayloadType(pt)
	ver, _ := packets.ReadB8(b, 16+1)
	h.MajorVersion = ver >> 4
	h.MinorVersion = ver & 0x0f
	et, _ := packets.ReadB8(b, 16+2)
	h.ExchangeType = IkeExchangeType(et)
	flags, _ := packets.ReadB8(b, 16+3)
	h.Flags = IkeFlags(flags)
	h.MsgId, _ = packets.ReadB32(b, 16+4)
	h.MsgLength, _ = packets.ReadB32(b, 16+8)
	if h.MsgLength < IKE_HEADER_LEN {
		log.V(LOG_CODEC).Infof("")
		return nil, ERR_INVALID_SYNTAX
	}
	log.V(LOG_CODEC).Infof("Ike Header: %+v from \n%s", *h, hex.Dump(b))
	return
}

func (h *IkeHeader) Encode() (b []byte) {
	b = make([]byte, IKE_HEADER_LEN)
	copy(b, h.SpiI[:])
	copy(b[8:], h.SpiR[:])
	packets.WriteB8(b, 16, uint8(h.NextPayload))
	packets.WriteB8(b, 17, h.MajorVersion<<4|h.MinorVersion)
	packets.WriteB8(b, 18, uint8(h.ExchangeType))
	packets.WriteB8(b, 19, uint8(h.Flags))
	packets.WriteB32(b, 20, h.MsgId)
	packets.WriteB32(b, 24, h.MsgLength)
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
const (
	PAYLOAD_HEADER_LENGTH = 4
)

type PayloadHeader struct {
	NextPayload   PayloadType
	IsCritical    bool
	PayloadLength uint16
}

func (h *PayloadHeader) NextPayloadType() PayloadType {
	return h.NextPayload
}

func encodePayloadHeader(pt PayloadType, plen uint16) (b []byte) {
	b = make([]byte, PAYLOAD_HEADER_LENGTH)
	packets.WriteB8(b, 0, uint8(pt))
	packets.WriteB16(b, 2, plen+PAYLOAD_HEADER_LENGTH)
	return
}
func (h *PayloadHeader) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC).Infof("Packet Too short : %d", len(b))
		return ERR_INVALID_SYNTAX
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	log.V(LOG_CODEC).Infof("Payload Header: %+v from \n%s", *h, hex.Dump(b))
	return
}

type Payload interface {
	Type() PayloadType
	Decode([]byte) error
	Encode() []byte
	NextPayloadType() PayloadType
}

// payloads

// start sa payload

type AttributeType uint16

const (
	ATTRIBUTE_TYPE_KEY_LENGTH AttributeType = 14
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |A|       Attribute Type        |    AF=0  Attribute Length     |
   |F|                             |    AF=1  Attribute Value      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   AF=0  Attribute Value                       |
   |                   AF=1  Not Transmitted                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type TransformAttribute struct {
	Type  AttributeType
	Value uint16 // fixed 2 octet length for now
}

const (
	MIN_LEN_ATTRIBUTE = 4
)

func decodeAttribute(b []byte) (attr *TransformAttribute, used int, err error) {
	if len(b) < MIN_LEN_ATTRIBUTE {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if at, _ := packets.ReadB16(b, 0); AttributeType(at&0x7fff) != ATTRIBUTE_TYPE_KEY_LENGTH {
		log.V(LOG_CODEC).Infof("wrong attribute type, 0x%x", at)
		err = ERR_INVALID_SYNTAX
		return
	}
	alen, _ := packets.ReadB16(b, 2)
	attr = &TransformAttribute{
		Type:  ATTRIBUTE_TYPE_KEY_LENGTH,
		Value: alen,
	}
	used = 4
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Last Substruc |   RESERVED    |        Transform Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Transform Type |   RESERVED    |          Transform ID         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                      Transform Attributes                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type Transform struct {
	IsLast      bool
	Type        TransformType
	TransformId uint16
	Attributes  []*TransformAttribute
}

const (
	MIN_LEN_TRANSFORM = 8
)

func decodeTransform(b []byte) (trans *Transform, used int, err error) {
	if len(b) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trans = &Transform{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		trans.IsLast = true
	}
	trLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(trLength) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if int(trLength) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trType, _ := packets.ReadB8(b, 4)
	trans.Type = TransformType(trType)
	trans.TransformId, _ = packets.ReadB16(b, 6)
	// variable parts
	b = b[MIN_LEN_TRANSFORM:int(trLength)]
	for len(b) > 0 {
		attr, attrUsed, attrErr := decodeAttribute(b)
		if attrErr != nil {
			err = attrErr
			return
		}
		b = b[attrUsed:]
		trans.Attributes = append(trans.Attributes, attr)
	}
	used = int(trLength)
	return
}
func encodeTransform(trans *Transform, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_TRANSFORM)
	if !isLast {
		packets.WriteB8(b, 0, 3)
	}
	packets.WriteB8(b, 4, uint8(trans.Type))
	packets.WriteB16(b, 6, trans.TransformId)
	if len(trans.Attributes) != 0 {
		// TODO - taken a shortcut for attribute
		attr := make([]byte, 4)
		packets.WriteB16(attr, 0, 0x8000|14) // key length in bits
		packets.WriteB16(attr, 2, trans.Attributes[0].Value)
		b = append(b, attr...)
	}
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Last Substruc |   RESERVED    |         Proposal Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                        SPI (variable)                         ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                        <Transforms>                           ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type Proposal struct {
	IsLast     bool
	Number     uint8
	ProtocolId ProtocolId
	Spi        []byte
	Transforms []*Transform
}

const (
	MIN_LEN_PROPOSAL = 8
)

func decodeProposal(b []byte) (prop *Proposal, used int, err error) {
	if len(b) < MIN_LEN_PROPOSAL {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	prop = &Proposal{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		prop.IsLast = true
	}
	propLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(propLength) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if int(propLength) < MIN_LEN_PROPOSAL {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	prop.Number, _ = packets.ReadB8(b, 4)
	pId, _ := packets.ReadB8(b, 5)
	prop.ProtocolId = ProtocolId(pId)
	spiSize, _ := packets.ReadB8(b, 6)
	numTransforms, _ := packets.ReadB8(b, 7)
	// variable parts
	if len(b) < MIN_LEN_PROPOSAL+int(spiSize) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	used = MIN_LEN_PROPOSAL + int(spiSize)
	prop.Spi = append([]byte{}, b[8:used]...)
	b = b[used:int(propLength)]
	for len(b) > 0 {
		trans, usedT, errT := decodeTransform(b)
		if errT != nil {
			err = errT
			return
		}
		prop.Transforms = append(prop.Transforms, trans)
		b = b[usedT:]
		if trans.IsLast {
			if len(b) > 0 {
				log.V(LOG_CODEC).Info("")
				err = ERR_INVALID_SYNTAX
				return
			}
			break
		}
	}
	if len(prop.Transforms) != int(numTransforms) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	used = int(propLength)
	return
}
func encodeProposal(prop *Proposal, number int, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_PROPOSAL)
	if !isLast {
		packets.WriteB8(b, 0, 2)
	}
	packets.WriteB8(b, 4, prop.Number)
	packets.WriteB8(b, 5, uint8(prop.ProtocolId))
	packets.WriteB8(b, 6, uint8(len(prop.Spi)))
	packets.WriteB8(b, 7, uint8(len(prop.Transforms)))
	b = append(b, prop.Spi...)
	for idx, tr := range prop.Transforms {
		var isLast bool
		if idx == len(prop.Transforms)-1 {
			isLast = true
		}
		b = append(b, encodeTransform(tr, isLast)...)
	}
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

type SaPayload struct {
	*PayloadHeader
	Proposals []*Proposal
}

func (s *SaPayload) Type() PayloadType { return PayloadTypeSA }
func (s *SaPayload) Encode() (b []byte) {
	for idx, prop := range s.Proposals {
		var isLast bool
		if idx == len(s.Proposals)-1 {
			isLast = true
		}
		b = append(b, encodeProposal(prop, idx+1, isLast)...)
	}
	return
}
func (s *SaPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	for len(b) > 0 {
		prop, used, errP := decodeProposal(b)
		if errP != nil {
			return errP
		}
		s.Proposals = append(s.Proposals, prop)
		b = b[used:]
		if prop.IsLast {
			if len(b) > 0 {
				log.V(LOG_CODEC).Info("")
				err = ERR_INVALID_SYNTAX
				return
			}
			break
		}
	}
	return
}

// end sa payload

// start ke payload
/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Diffie-Hellman Group Num    |           RESERVED            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Key Exchange Data                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type KePayload struct {
	*PayloadHeader
	DhTransformId DhTransformId
	KeyData       *big.Int
}

func (s *KePayload) Type() PayloadType { return PayloadTypeKE }
func (s *KePayload) Encode() (b []byte) {
	b = make([]byte, 4)
	packets.WriteB16(b, 0, uint16(s.DhTransformId))
	return append(b, s.KeyData.Bytes()...)
}
func (s *KePayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	gn, _ := packets.ReadB16(b, 0)
	s.DhTransformId = DhTransformId(gn)
	s.KeyData = new(big.Int).SetBytes(b[4:])
	return
}

type IdType uint8

const (
	ID_IPV4_ADDR   IdType = 1
	ID_FQDN        IdType = 2
	ID_RFC822_ADDR IdType = 3
	ID_IPV6_ADDR   IdType = 5
	ID_DER_ASN1_DN IdType = 9
	ID_DER_ASN1_GN IdType = 10
	ID_KEY_ID      IdType = 11
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ID Type     |                 RESERVED                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                   Identification Data                         ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type IdPayload struct {
	*PayloadHeader
	IdPayloadType PayloadType
	IdType        IdType
	Data          []byte
}

func (s *IdPayload) Type() PayloadType { return s.IdPayloadType }
func (s *IdPayload) Encode() (b []byte) {
	b = []byte{uint8(s.IdType), 0, 0, 0}
	return append(b, s.Data...)
}
func (s *IdPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	Idt, _ := packets.ReadB8(b, 0)
	s.IdType = IdType(Idt)
	s.Data = append([]byte{}, b[4:]...)
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Cert Encoding |                                               |
   +-+-+-+-+-+-+-+-+                                               |
   ~                       Certificate Data                        ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type CertPayload struct {
	*PayloadHeader
}

func (s *CertPayload) Type() PayloadType  { return PayloadTypeCERT }
func (s *CertPayload) Encode() (b []byte) { return }
func (s *CertPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	// TODO
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Cert Encoding |                                               |
   +-+-+-+-+-+-+-+-+                                               |
   ~                    Certification Authority                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type CertRequestPayload struct {
	*PayloadHeader
}

func (s *CertRequestPayload) Type() PayloadType  { return PayloadTypeCERTREQ }
func (s *CertRequestPayload) Encode() (b []byte) { return }
func (s *CertRequestPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	// TODO
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Auth Method   |                RESERVED                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                      Authentication Data                      ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type AuthMethod uint8

const (
	RSA_DIGITAL_SIGNATURE             AuthMethod = 1
	SHARED_KEY_MESSAGE_INTEGRITY_CODE AuthMethod = 2
	DSS_DIGITAL_SIGNATURE             AuthMethod = 3
)

type AuthPayload struct {
	*PayloadHeader
	Method AuthMethod
	Data   []byte
}

func (s *AuthPayload) Type() PayloadType { return PayloadTypeAUTH }
func (s *AuthPayload) Encode() (b []byte) {
	b = []byte{uint8(s.Method), 0, 0, 0}
	return append(b, s.Data...)
}
func (s *AuthPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	authMethod, _ := packets.ReadB8(b, 0)
	s.Method = AuthMethod(authMethod)
	s.Data = append([]byte{}, b[4:]...)
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                            Nonce Data                         ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type NoncePayload struct {
	*PayloadHeader
	Nonce *big.Int
}

func (s *NoncePayload) Type() PayloadType {
	return PayloadTypeNonce
}
func (s *NoncePayload) Encode() (b []byte) {
	return s.Nonce.Bytes()
}
func (s *NoncePayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	// between 16 and 256 octets
	if len(b) < 16 || len(b) > 256 {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	s.Nonce = new(big.Int).SetBytes(b)
	return
}

type NotificationType uint16

const (
	// Error types
	UNSUPPORTED_CRITICAL_PAYLOAD NotificationType = 1
	INVALID_IKE_SPI              NotificationType = 4
	INVALID_MAJOR_VERSION        NotificationType = 5
	INVALID_SYNTAX               NotificationType = 7
	INVALID_MESSAGE_ID           NotificationType = 9
	INVALID_SPI                  NotificationType = 11
	NO_PROPOSAL_CHOSEN           NotificationType = 14
	INVALID_KE_PAYLOAD           NotificationType = 17
	AUTHENTICATION_FAILED        NotificationType = 24
	SINGLE_PAIR_REQUIRED         NotificationType = 34
	NO_ADDITIONAL_SAS            NotificationType = 35
	INTERNAL_ADDRESS_FAILURE     NotificationType = 36
	FAILED_CP_REQUIRED           NotificationType = 37
	TS_UNACCEPTABLE              NotificationType = 38
	INVALID_SELECTORS            NotificationType = 39
	TEMPORARY_FAILURE            NotificationType = 43
	CHILD_SA_NOT_FOUND           NotificationType = 44
	// Status Types
	INITIAL_CONTACT               NotificationType = 16384
	SET_WINDOW_SIZE               NotificationType = 16385
	ADDITIONAL_TS_POSSIBLE        NotificationType = 16386
	IPCOMP_SUPPORTED              NotificationType = 16387
	NAT_DETECTION_SOURCE_IP       NotificationType = 16388
	NAT_DETECTION_DESTINATION_IP  NotificationType = 16389
	COOKIE                        NotificationType = 16390
	USE_TRANSPORT_MODE            NotificationType = 16391
	HTTP_CERT_LOOKUP_SUPPORTED    NotificationType = 16392
	REKEY_SA                      NotificationType = 16393
	ESP_TFC_PADDING_NOT_SUPPORTED NotificationType = 16394
	NON_FIRST_FRAGMENTS_ALSO      NotificationType = 16395
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Protocol ID  |   SPI Size    |      Notify Message Type      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                Security Parameter Index (SPI)                 ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Notification Data                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type NotifyPayload struct {
	*PayloadHeader
	ProtocolId       ProtocolId
	NotificationType NotificationType
	Spi              []byte
	Data             []byte
}

func (s *NotifyPayload) Type() PayloadType {
	return PayloadTypeN
}
func (s *NotifyPayload) Encode() (b []byte) { return }
func (s *NotifyPayload) Decode(b []byte) (err error) {
	pId, _ := packets.ReadB8(b, 0)
	s.ProtocolId = ProtocolId(pId)
	spiLen, _ := packets.ReadB8(b, 1)
	if len(b) < 4+int(spiLen) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	nType, _ := packets.ReadB16(b, 2)
	s.NotificationType = NotificationType(nType)
	s.Spi = append([]byte{}, b[4:spiLen+4]...)
	s.Data = append([]byte{}, b[spiLen+4:]...)
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Protocol ID   |   SPI Size    |          Num of SPIs          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~               Security Parameter Index(es) (SPI)              ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type DeletePayload struct {
	*PayloadHeader
}

func (s *DeletePayload) Type() PayloadType {
	return PayloadTypeD
}
func (s *DeletePayload) Encode() (b []byte) { return }
func (s *DeletePayload) Decode(b []byte) (err error) {
	// TODO
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                        Vendor ID (VID)                        ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type VendorIdPayload struct {
	*PayloadHeader
}

func (s *VendorIdPayload) Type() PayloadType {
	return PayloadTypeV
}
func (s *VendorIdPayload) Encode() (b []byte) { return }
func (s *VendorIdPayload) Decode(b []byte) (err error) {
	// TODO
	return
}

// start of traffic selector
type SelectorType uint8

const (
	TS_IPV4_ADDR_RANGE SelectorType = 7
	TS_IPV6_ADDR_RANGE SelectorType = 8
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   TS Type     |IP Protocol ID*|       Selector Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Start Port*         |           End Port*           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Starting Address*                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Ending Address*                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
const (
	MIN_LEN_SELECTOR = 8
)

type Selector struct {
	Type                     SelectorType
	IpProtocolId             uint8
	StartPort, Endport       uint16
	StartAddress, EndAddress net.IP
}

func decodeSelector(b []byte) (sel *Selector, used int, err error) {
	if len(b) < MIN_LEN_SELECTOR {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	stype, _ := packets.ReadB8(b, 0)
	id, _ := packets.ReadB8(b, 1)
	slen, _ := packets.ReadB16(b, 2)
	if len(b) < int(slen) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	sport, _ := packets.ReadB16(b, 8)
	eport, _ := packets.ReadB16(b, 10)
	iplen := net.IPv4len
	if SelectorType(stype) == TS_IPV6_ADDR_RANGE {
		iplen = net.IPv6len
	}
	if len(b) < 8+2*iplen {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	sel = &Selector{
		Type:         SelectorType(stype),
		IpProtocolId: id,
		StartPort:    sport,
		Endport:      eport,
		StartAddress: append([]byte{}, b[8:8+iplen]...),
		EndAddress:   append([]byte{}, b[8+iplen:8+2*iplen]...),
	}
	used = 8 + 2*iplen
	return
}
func encodeSelector(sel *Selector) (b []byte) {
	b = make([]byte, MIN_LEN_SELECTOR)
	packets.WriteB8(b, 0, uint8(sel.Type))
	packets.WriteB8(b, 1, uint8(sel.IpProtocolId))
	packets.WriteB16(b, 4, uint16(sel.StartPort))
	packets.WriteB16(b, 6, uint16(sel.Endport))
	b = append(b, sel.StartAddress...)
	b = append(b, sel.EndAddress...)
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Number of TSs |                 RESERVED                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       <Traffic Selectors>                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
const (
	MIN_LEN_TRAFFIC_SELECTOR = 4
)

type TrafficSelectorPayload struct {
	*PayloadHeader
	TrafficSelectorPayloadType PayloadType
	Selectors                  []*Selector
}

func (s *TrafficSelectorPayload) Type() PayloadType { return s.TrafficSelectorPayloadType }
func (s *TrafficSelectorPayload) Encode() (b []byte) {
	b = []byte{uint8(len(s.Selectors)), 0, 0, 0}
	for _, sel := range s.Selectors {
		b = append(b, encodeSelector(sel)...)
	}
	return
}
func (s *TrafficSelectorPayload) Decode(b []byte) (err error) {
	if len(b) < MIN_LEN_TRAFFIC_SELECTOR {
		err = ERR_INVALID_SYNTAX
		log.V(LOG_CODEC).Info("")
		return
	}
	numSel, _ := packets.ReadB8(b, 0)
	b = b[4:]
	for len(b) > 0 {
		sel, used, serr := decodeSelector(b)
		if serr != nil {
			err = serr
			log.V(LOG_CODEC).Info("")
			return
		}
		s.Selectors = append(s.Selectors, sel)
		b = b[used:]
		if len(s.Selectors) >= int(numSel) {
			err = ERR_INVALID_SYNTAX
			log.V(LOG_CODEC).Info("")
			return
		}
	}
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Initialization Vector                     |
   |         (length is block size for encryption algorithm)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Encrypted IKE Payloads                     ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |             Padding (0-255 octets)            |
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   |                                               |  Pad Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Integrity Checksum Data                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func VerifyDecrypt(tkm *Tkm, ike []byte, b []byte) (dec []byte, err error) {
	if tkm == nil {
		return nil, errors.New("cant decrypt, no tkm found")
	}
	if err = tkm.VerifyMac(ike); err != nil {
		return nil, err
	}
	return tkm.Decrypt(b)
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C| RESERVED    |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   CFG Type    |                    RESERVED                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                   Configuration Attributes                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ConfigurationPayload struct {
	*PayloadHeader
}

func (s *ConfigurationPayload) Type() PayloadType  { return PayloadTypeCP }
func (s *ConfigurationPayload) Encode() (b []byte) { return }
func (s *ConfigurationPayload) Decode(b []byte) (err error) {
	// TODO
	return
}

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       EAP Message                             ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type EapPayload struct {
	*PayloadHeader
}

func (s *EapPayload) Type() PayloadType  { return PayloadTypeEAP }
func (s *EapPayload) Encode() (b []byte) { return }
func (s *EapPayload) Decode(b []byte) (err error) {
	// TODO
	return
}

// IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]

// IKE_AUTH
// a->b
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Initiator, Message ID=1)
//  SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr,  N(INITIAL_CONTACT)}
// b->a
//  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags: Response, Message ID=1)
//  SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}

// INFORMATIONAL
// b<-a
//  HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: none, Message ID=m),
//  SK {...}
// a<-b
// 	HDR(SPIi=xxx, SPIr=yyy, INFORMATIONAL, Flags: Initiator | Response, Message ID=m),
//  SK {}

// CREATE_CHILD_SA
// b<-a
//  HDR(SPIi=xxx, SPIy=yyy, CREATE_CHILD_SA, Flags: none, Message ID=m),
//  SK {...}
// a<-b
//  HDR(SPIi=xxx, SPIr=yyy, CREATE_CHILD_SA, Flags: Initiator | Response, Message ID=m),
//  SK {N(NO_ADDITIONAL_SAS)}

type Payloads map[PayloadType]Payload
type Message struct {
	IkeHeader *IkeHeader
	Payloads  Payloads
}

func (s *Message) DecodeHeader(b []byte) (err error) {
	s.IkeHeader, err = DecodeIkeHeader(b[:IKE_HEADER_LEN])
	return
}

func (s *Message) DecodePayloads(ib []byte, tkm *Tkm) (err error) {
	s.Payloads = make(Payloads)
	if len(ib) < int(s.IkeHeader.MsgLength) {
		log.V(LOG_CODEC).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	nextPayload := s.IkeHeader.NextPayload
	b := ib[IKE_HEADER_LEN:s.IkeHeader.MsgLength]
	if nextPayload == PayloadTypeSK {
		pHeader := &PayloadHeader{}
		if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
			return
		}
		nextPayload = pHeader.NextPayload
		if b, err = VerifyDecrypt(tkm, ib, b[PAYLOAD_HEADER_LENGTH:pHeader.PayloadLength]); err != nil {
			return
		}
	}
	for nextPayload != PayloadTypeNone {
		pHeader := &PayloadHeader{}
		if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
			return
		}
		var payload Payload
		switch nextPayload {
		case PayloadTypeSA:
			payload = &SaPayload{PayloadHeader: pHeader}
		case PayloadTypeKE:
			payload = &KePayload{PayloadHeader: pHeader}
		case PayloadTypeIDi:
			payload = &IdPayload{PayloadHeader: pHeader, IdPayloadType: PayloadTypeIDi}
		case PayloadTypeIDr:
			payload = &IdPayload{PayloadHeader: pHeader, IdPayloadType: PayloadTypeIDr}
		case PayloadTypeCERT:
			payload = &CertPayload{PayloadHeader: pHeader}
		case PayloadTypeCERTREQ:
			payload = &CertRequestPayload{PayloadHeader: pHeader}
		case PayloadTypeAUTH:
			payload = &AuthPayload{PayloadHeader: pHeader}
		case PayloadTypeNonce:
			payload = &NoncePayload{PayloadHeader: pHeader}
		case PayloadTypeN:
			payload = &NotifyPayload{PayloadHeader: pHeader}
		case PayloadTypeD:
			payload = &DeletePayload{PayloadHeader: pHeader}
		case PayloadTypeV:
			payload = &VendorIdPayload{PayloadHeader: pHeader}
		case PayloadTypeTSi:
			payload = &TrafficSelectorPayload{PayloadHeader: pHeader, TrafficSelectorPayloadType: PayloadTypeTSi}
		case PayloadTypeTSr:
			payload = &TrafficSelectorPayload{PayloadHeader: pHeader, TrafficSelectorPayloadType: PayloadTypeTSr}
		case PayloadTypeCP:
			payload = &ConfigurationPayload{PayloadHeader: pHeader}
		case PayloadTypeEAP:
			payload = &EapPayload{PayloadHeader: pHeader}
		}
		pbuf := b[PAYLOAD_HEADER_LENGTH:pHeader.PayloadLength]
		if err = payload.Decode(pbuf); err != nil {
			return
		}
		nextPayload = pHeader.NextPayload
		b = b[pHeader.PayloadLength:]
		s.Payloads[payload.Type()] = payload
	}
	return
}

func (s *Message) Encode() (b []byte) {
	ty := s.IkeHeader.NextPayload
	for ty != PayloadTypeNone {
		pl := s.Payloads[ty]
		body := pl.Encode()
		ty = pl.NextPayloadType()
		hdr := encodePayloadHeader(ty, uint16(len(body)))
		b = append(b, hdr...)
		b = append(b, body...)
	}
	s.IkeHeader.MsgLength = uint32(len(b) + IKE_HEADER_LEN)
	b = append(s.IkeHeader.Encode(), b...)
	return
}
