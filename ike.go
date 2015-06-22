package ike

import (
	"msgbox.io/log"
	"msgbox.io/packets"
)

const (
	IKE_PORT      = 500
	IKE_NATT_PORT = 4500
)

// mimimal impl

// IKE_SA_INIT and IKE_AUTH
// to create IKE SA and the first child SA.

// understand CREATE_CHILD_SA request so it can
// reply with CREATE_CHILD_SA error response saying NO_ADDITIONAL_SAS

// understand INFORMATIONAL request so much, it can reply
// with empty INFORMATIONAL response

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
	PayloadTypeNi      PayloadType = 40 // Nonce
	PayloadTypeNr      PayloadType = 40 // Nonce
	PayloadTypeN       PayloadType = 41 // Notify
	PayloadTypeD       PayloadType = 42 // Delete
	PayloadTypeV       PayloadType = 43 // Vendor ID
	PayloadTypeTSi     PayloadType = 44 // Traffic Selector - Initiator
	PayloadTypeTSr     PayloadType = 45 // Traffic Selector - Responder
	PayloadTypeSK      PayloadType = 46 // Encrypted and Authenticated
	PayloadTypeCP      PayloadType = 47 // Configuration
	PayloadTypeEAP     PayloadType = 48 // Extensible Authentication
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
	IKE ProtocolId = 1
	AH  ProtocolId = 2
	ESP ProtocolId = 3
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

type EsnTranformid uint16

const (
	ESN_NONE EsnTranformid = 0
	ESN      EsnTranformid = 1
)

/*
                        1                   2                   3
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
	Id                         uint32
	MsgLength                  uint32
}

func (h *IkeHeader) Decode(b []byte) (err error) {
	if len(b) < IKE_HEADER_LEN {
		log.V(LOG_CODEC).Infof("Packet Too short : %d", len(b))
		return INVALID_SYNTAX
	}
	copy(h.SpiI[:], b)
	copy(h.SpiR[:], b[8:])
	pt, _ := packets.ReadB8(b, 16)
	h.NextPayload = PayloadType(pt)
	ver, _ := packets.ReadB8(b, 16+1)
	h.MajorVersion = ver >> 4
	h.MinorVersion = ver | 0x0f
	et, _ := packets.ReadB8(b, 16+2)
	h.ExchangeType = IkeExchangeType(et)
	flags, _ := packets.ReadB8(b, 16+3)
	h.Flags = IkeFlags(flags)
	h.Id, _ = packets.ReadB32(b, 16+4)
	h.MsgLength, _ = packets.ReadB32(b, 16+8)
	return

}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type PayloadHeader struct {
	NextPayload   PayloadType
	IsCritical    bool
	PayloadLength uint16
}

func (h *PayloadHeader) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC).Infof("Packet Too short : %d", len(b))
		return INVALID_SYNTAX
	}
	pt, _ := packets.ReadB8(b, 0)
	h.NextPayload = PayloadType(pt)
	if c, _ := packets.ReadB8(b, 1); c&0x80 == 1 {
		h.IsCritical = true
	}
	h.PayloadLength, _ = packets.ReadB16(b, 2)
	return
}

type Payload interface {
	Type() PayloadType
	Decode([]byte) error
	Encode() []byte
}

//

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |A|       Attribute Type        |    AF=0  Attribute Length     |
   |F|                             |    AF=1  Attribute Value      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   AF=0  Attribute Value                       |
   |                   AF=1  Not Transmitted                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type TransformAttributes struct {
}

/*
                       1                   2                   3
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
	Length      uint16
	Type        TransformType
	TransformId uint16
}

func decodeTransform(b []byte) (trans *Transform, used int, err error) {
	return
}

/*
                        1                   2                   3
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
	Length     uint16
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
		err = INVALID_SYNTAX
		return
	}
	prop = &Proposal{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		prop.IsLast = true
	}
	prop.Length, _ = packets.ReadB16(b, 2)
	prop.Number, _ = packets.ReadB8(b, 4)
	pId, _ := packets.ReadB8(b, 5)
	prop.ProtocolId = ProtocolId(pId)
	spiSize, _ := packets.ReadB8(b, 6)
	numTransforms, _ := packets.ReadB8(b, 7)
	// variable parts
	used = 8
	if len(b) < 8+int(spiSize) {
		log.V(LOG_CODEC).Info("")
		err = INVALID_SYNTAX
		return
	}
	used = 8 + int(spiSize)
	prop.Spi = append([]byte{}, b[8:used]...)
	b = b[used:]
	for len(b) > 0 {
		trans, usedT, errT := decodeTransform(b)
		if errT != nil {
			err = errT
			return
		}
		prop.Transforms = append(prop.Transforms, trans)
		b = b[usedT:]
	}
	if len(prop.Transforms) != int(numTransforms) {
		log.V(LOG_CODEC).Info("")
		err = INVALID_SYNTAX
		return
	}
	return
}

type SaPayload struct {
	Header    PayloadHeader
	Proposals []*Proposal
}

func (s *SaPayload) Type() PayloadType { return PayloadTypeSA }
func (s *SaPayload) Decode(b []byte) (err error) {
	// header has already been decoded
	for len(b) > 0 {
		prop, used, err := decodeProposal(b)
		if err != nil {
			return err
		}
		s.Proposals = append(s.Proposals, prop)
		b = b[used:]
	}
	return
}

// 2.1.2 IKE_SA_INIT
// a->b
//	HDR(SPIi=xxx, SPIr=0, IKE_SA_INIT, Flags: Initiator, Message ID=0),
//	SAi1, KEi, Ni
// b->a
//	HDR((SPIi=xxx, SPIr=yyy, IKE_SA_INIT, Flags: Response, Message ID=0),
// 	SAr1, KEr, Nr, [CERTREQ]

type SaInit struct {
	IkeHeader
}

func (s *SaInit) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC).Info("")
		return INVALID_SYNTAX
	}
	return
}

// 2.1.3 IKE_AUTH
// a->b HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr}
// b->a HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
