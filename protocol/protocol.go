package protocol

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"time"

	"msgbox.io/log"
	"msgbox.io/packets"
)

const (
	IKE_PORT      = 500
	IKE_NATT_PORT = 4500
)

const (
	LOG_PACKET_JS = 3
	LOG_CODEC     = 4
	LOG_CODEC_ERR = 2
)

type Packet interface {
	Decode([]byte) error
	Encode() []byte
}

const (
	IKEV2_MAJOR_VERSION = 2
	IKEV2_MINOR_VERSION = 0
)

type Spi []byte

type IkeExchangeType uint16

const (
	// 0-33	Reserved	[RFC7296]
	IKE_SA_INIT        IkeExchangeType = 34 //	[RFC7296]
	IKE_AUTH           IkeExchangeType = 35 //	[RFC7296]
	CREATE_CHILD_SA    IkeExchangeType = 36 //	[RFC7296]
	INFORMATIONAL      IkeExchangeType = 37 //	[RFC7296]
	IKE_SESSION_RESUME IkeExchangeType = 38 //	[RFC5723]
	GSA_AUTH           IkeExchangeType = 39 //	[draft-yeung-g-ikev2]
	GSA_REGISTRATION   IkeExchangeType = 40 //	[draft-yeung-g-ikev2]
	GSA_REKEY          IkeExchangeType = 41 //	[draft-yeung-g-ikev2]
	// 42-239	Unassigned
	// 240-255	Private use	[RFC7296]
)

type PayloadType uint8

const (
	PayloadTypeNone PayloadType = 0 // No Next Payload		[RFC7296]
	// 1-32	Reserved		[RFC7296]
	PayloadTypeSA      PayloadType = 33 // Security Association	 [RFC7296]
	PayloadTypeKE      PayloadType = 34 // Key Exchange	 [RFC7296]
	PayloadTypeIDi     PayloadType = 35 // Identification - Initiator	 [RFC7296]
	PayloadTypeIDr     PayloadType = 36 // Identification - Responder	 [RFC7296]
	PayloadTypeCERT    PayloadType = 37 // Certificate	 [RFC7296]
	PayloadTypeCERTREQ PayloadType = 38 // Certificate Request	 [RFC7296]
	PayloadTypeAUTH    PayloadType = 39 // Authentication	 [RFC7296]
	PayloadTypeNonce   PayloadType = 40 // Nonce	Ni, Nr [RFC7296]
	PayloadTypeN       PayloadType = 41 // Notify	 [RFC7296]
	PayloadTypeD       PayloadType = 42 // Delete	 [RFC7296]
	PayloadTypeV       PayloadType = 43 // Vendor ID	 [RFC7296]
	PayloadTypeTSi     PayloadType = 44 // Traffic Selector - Initiator	 [RFC7296]
	PayloadTypeTSr     PayloadType = 45 // Traffic Selector - Responder	 [RFC7296]
	PayloadTypeSK      PayloadType = 46 // Encrypted and Authenticated	 [RFC7296]
	PayloadTypeCP      PayloadType = 47 // Configuration	 [RFC7296]
	PayloadTypeEAP     PayloadType = 48 // Extensible Authentication	 [RFC7296]
	PayloadTypeGSPM    PayloadType = 49 // Generic Secure Password Method	 [RFC6467]
	PayloadTypeIDg     PayloadType = 50 // Group Identification	[draft-yeung-g-ikev2]
	PayloadTypeGSA     PayloadType = 51 // Group Security Association		[draft-yeung-g-ikev2]
	PayloadTypeKD      PayloadType = 52 // Key Download		[draft-yeung-g-ikev2]
	PayloadTypeSKF     PayloadType = 53 // Encrypted and Authenticated Fragment	 [RFC7383]
	// 54-127	Unassigned
	// 128-255	Private use		[RFC7296]
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
	TRANSFORM_TYPE_ENCR  TransformType = 1 // Encryption Algorithm  used in IKE and ESP [RFC7296]
	TRANSFORM_TYPE_PRF   TransformType = 2 // Pseudorandom Function used in IKE [RFC7296]
	TRANSFORM_TYPE_INTEG TransformType = 3 // Integrity Algorithm  used in   IKE*, AH, optional in ESP [RFC7296]
	TRANSFORM_TYPE_DH    TransformType = 4 // Diffie-Hellman Group used in   IKE, optional in AH & ESP [RFC7296]
	TRANSFORM_TYPE_ESN   TransformType = 5 // Extended Sequence Numbers used in AH and ESP [RFC7296]
)

type EncrTransformId uint16

const (
	// Name -                               ESP ref - IKE ref
	// Reserved	[RFC7296]	-0	//
	ENCR_DES_IV64 EncrTransformId = 1 //    [RFC1827]	-
	ENCR_DES      EncrTransformId = 2 //	[RFC2405]	[RFC7296]
	ENCR_3DES     EncrTransformId = 3 //	[RFC2451]	[RFC7296]
	ENCR_RC5      EncrTransformId = 4 //	[RFC2451]	[RFC7296]
	ENCR_IDEA     EncrTransformId = 5 //	[RFC2451]	[RFC7296]
	ENCR_CAST     EncrTransformId = 6 //	[RFC2451]	[RFC7296]
	ENCR_BLOWFISH EncrTransformId = 7 //	[RFC2451]	[RFC7296]
	ENCR_3IDEA    EncrTransformId = 8 //	[RFC2451]	[RFC7296]
	ENCR_DES_IV32 EncrTransformId = 9 //	[RFC7296]	-
	// Reserved                       //	[RFC7296]	-
	ENCR_NULL    EncrTransformId = 11 //	[RFC2410]	Not allowed
	ENCR_AES_CBC EncrTransformId = 12 //	[RFC3602]	[RFC7296]
	ENCR_AES_CTR EncrTransformId = 13 //	[RFC3686]	[RFC5930]
	// CCM, 8B IV & _*B ICV
	AEAD_AES_CCM_SHORT_8  EncrTransformId = 14 // 128 & 256b keys [RFC4309]	[RFC5282]
	AEAD_AES_CCM_SHORT_12 EncrTransformId = 15 // 128 & 256b keys [RFC4309]	[RFC5282]
	AEAD_AES_CCM_SHORT_16 EncrTransformId = 16 // 128 & 256b keys [RFC4309]	[RFC5282]
	// Unassigned
	// GCM, 8B IV & _*B ICV
	AEAD_AES_GCM_8  EncrTransformId = 18 // 128, 196 & 256b keys [RFC4106] [RFC5282]
	AEAD_AES_GCM_12 EncrTransformId = 19 // 128, 196 & 256b keys [RFC4106] [RFC5282]
	AEAD_AES_GCM_16 EncrTransformId = 20 // 128, 196 & 256b keys [RFC4106] [RFC5282]
	// NULL, not really used
	ENCR_NULL_AUTH_AES_GMAC EncrTransformId = 21 //[RFC4543]	Not allowed
	// Reserved for IEEE P1619 XTS-AES
	ENCR_CAMELLIA_CBC        EncrTransformId = 23 //[RFC5529]	[RFC5529]
	ENCR_CAMELLIA_CTR        EncrTransformId = 24 //[RFC5529]	-
	ENCR_CAMELLIA_CCM_8_ICV  EncrTransformId = 25 //[RFC5529]	-
	ENCR_CAMELLIA_CCM_12_ICV EncrTransformId = 26 //[RFC5529]	-
	ENCR_CAMELLIA_CCM_16_ICV EncrTransformId = 27 //[RFC5529]	-
	// 28-1023	Unassigned
	// 1024-65535	Private use	                  //[RFC7296]	[RFC7296]
)

type PrfTransformId uint16

const (
	// 0	Reserved	[RFC7296]
	PRF_HMAC_MD5      PrfTransformId = 1 //	[RFC2104]
	PRF_HMAC_SHA1     PrfTransformId = 2 //	[RFC2104]
	PRF_HMAC_TIGER    PrfTransformId = 3 //	[RFC2104]
	PRF_AES128_XCBC   PrfTransformId = 4 //	[RFC4434]
	PRF_HMAC_SHA2_256 PrfTransformId = 5 //	[RFC4868]
	PRF_HMAC_SHA2_384 PrfTransformId = 6 //	[RFC4868]
	PRF_HMAC_SHA2_512 PrfTransformId = 7 //	[RFC4868]
	PRF_AES128_CMAC   PrfTransformId = 8 //	[RFC4615]
	// 9-1023	Unassigned
	// 1024-65535	Private use	[RFC7296]
)

type AuthTransformId uint16

const (
	AUTH_NONE              AuthTransformId = 0  //	[RFC7296]
	AUTH_HMAC_MD5_96       AuthTransformId = 1  //	[RFC2403][RFC7296]
	AUTH_HMAC_SHA1_96      AuthTransformId = 2  //	[RFC2404][RFC7296]
	AUTH_DES_MAC           AuthTransformId = 3  //	[RFC7296]
	AUTH_KPDK_MD5          AuthTransformId = 4  //	[RFC7296]
	AUTH_AES_XCBC_96       AuthTransformId = 5  //	[RFC3566][RFC7296]
	AUTH_HMAC_MD5_128      AuthTransformId = 6  //	[RFC4595]
	AUTH_HMAC_SHA1_160     AuthTransformId = 7  //	[RFC4595]
	AUTH_AES_CMAC_96       AuthTransformId = 8  //	[RFC4494]
	AUTH_AES_128_GMAC      AuthTransformId = 9  //	[RFC4543]
	AUTH_AES_192_GMAC      AuthTransformId = 10 //	[RFC4543]
	AUTH_AES_256_GMAC      AuthTransformId = 11 //	[RFC4543]
	AUTH_HMAC_SHA2_256_128 AuthTransformId = 12 //	[RFC4868]
	AUTH_HMAC_SHA2_384_192 AuthTransformId = 13 //	[RFC4868]
	AUTH_HMAC_SHA2_512_256 AuthTransformId = 14 //	[RFC4868]
	// 15-1023	Unassigned
	// 1024-65535	Private use	[RFC7296]
)

type DhTransformId uint16

const (
	MODP_NONE DhTransformId = 0 // [RFC7296]
	MODP_768  DhTransformId = 1 // [RFC6989], Sec. 2.1	[RFC7296]
	MODP_1024 DhTransformId = 2 // [RFC6989], Sec. 2.1	[RFC7296]
	// 3-4	Reserved		[RFC7296]
	MODP_1536 DhTransformId = 5 // [RFC6989], Sec. 2.1	[RFC3526]
	// 6-13	Unassigned		[RFC7296]
	MODP_2048           DhTransformId = 14 // [RFC6989], Sec. 2.1	[RFC3526]
	MODP_3072           DhTransformId = 15 // [RFC6989], Sec. 2.1	[RFC3526]
	MODP_4096           DhTransformId = 16 // [RFC6989], Sec. 2.1	[RFC3526]
	MODP_6144           DhTransformId = 17 // [RFC6989], Sec. 2.1	[RFC3526]
	MODP_8192           DhTransformId = 18 // [RFC6989], Sec. 2.1	[RFC3526]
	ECP_256             DhTransformId = 19 // [RFC6989], Sec. 2.3	[RFC5903]
	ECP_384             DhTransformId = 20 // [RFC6989], Sec. 2.3	[RFC5903]
	ECP_521             DhTransformId = 21 // [RFC6989], Sec. 2.3	[RFC5903]
	MODP_1024_PRIME_160 DhTransformId = 22 // [RFC6989], Sec. 2.2	[RFC5114]
	MODP_2048_PRIME_224 DhTransformId = 23 // [RFC6989], Sec. 2.2	[RFC5114]
	MODP_2048_PRIME_256 DhTransformId = 24 // [RFC6989], Sec. 2.2	[RFC5114]
	ECP_192             DhTransformId = 25 // [RFC6989], Sec. 2.3	[RFC5114]
	ECP_224             DhTransformId = 26 // [RFC6989], Sec. 2.3	[RFC5114]
	BRAINPOOLP224R1     DhTransformId = 27 // [RFC6989], Sec. 2.3	[RFC6954]
	BRAINPOOLP256R1     DhTransformId = 28 // [RFC6989], Sec. 2.3	[RFC6954]
	BRAINPOOLP384R1     DhTransformId = 29 // [RFC6989], Sec. 2.3	[RFC6954]
	BRAINPOOLP512R1     DhTransformId = 30 // [RFC6989], Sec. 2.3	[RFC6954]
	// 31-1023	Unassigned
	// 1024-65535	Reserved for Private Use		[RFC7296]
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
		log.V(LOG_CODEC_ERR).Infof("Packet Too short : %d", len(b))
		return nil, ERR_INVALID_SYNTAX
	}
	h.SpiI = append([]byte{}, b[:8]...)
	h.SpiR = append([]byte{}, b[8:16]...)
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
		log.V(LOG_CODEC_ERR).Infof("")
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
	log.V(LOG_CODEC).Infof("Ike Header: %+v to \n%s", *h, hex.Dump(b))
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
func (h *PayloadHeader) Header() *PayloadHeader {
	return h
}
func (h PayloadHeader) Encode() (b []byte) {
	b = make([]byte, PAYLOAD_HEADER_LENGTH)
	packets.WriteB8(b, 0, uint8(h.NextPayload))
	packets.WriteB16(b, 2, h.PayloadLength+PAYLOAD_HEADER_LENGTH)
	log.V(LOG_CODEC).Infof("Payload Header: %+v to \n%s", h, hex.Dump(b))
	return
}
func (h *PayloadHeader) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Infof("Packet Too short : %d", len(b))
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
	Header() *PayloadHeader
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
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if at, _ := packets.ReadB16(b, 0); AttributeType(at&0x7fff) != ATTRIBUTE_TYPE_KEY_LENGTH {
		log.V(LOG_CODEC_ERR).Infof("wrong attribute type, 0x%x", at)
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
	Type        TransformType
	TransformId uint16
}

type SaTransform struct {
	Transform Transform
	KeyLength uint16
	IsLast    bool
}

const (
	MIN_LEN_TRANSFORM = 8
)

func decodeTransform(b []byte) (trans *SaTransform, used int, err error) {
	if len(b) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trans = &SaTransform{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		trans.IsLast = true
	}
	trLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(trLength) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if int(trLength) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trType, _ := packets.ReadB8(b, 4)
	trans.Transform.Type = TransformType(trType)
	trans.Transform.TransformId, _ = packets.ReadB16(b, 6)
	// variable parts
	b = b[MIN_LEN_TRANSFORM:int(trLength)]
	attrs := make(map[AttributeType]*TransformAttribute)
	for len(b) > 0 {
		attr, attrUsed, attrErr := decodeAttribute(b)
		if attrErr != nil {
			err = attrErr
			return
		}
		b = b[attrUsed:]
		attrs[attr.Type] = attr
	}
	if at, ok := attrs[ATTRIBUTE_TYPE_KEY_LENGTH]; ok {
		trans.KeyLength = at.Value
	}
	used = int(trLength)
	return
}
func encodeTransform(trans *SaTransform, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_TRANSFORM)
	if !isLast {
		packets.WriteB8(b, 0, 3)
	}
	packets.WriteB8(b, 4, uint8(trans.Transform.Type))
	packets.WriteB16(b, 6, trans.Transform.TransformId)
	if trans.KeyLength != 0 {
		// TODO - taken a shortcut for attribute
		attr := make([]byte, 4)
		packets.WriteB16(attr, 0, 0x8000|14) // key length in bits
		packets.WriteB16(attr, 2, trans.KeyLength)
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
type SaProposal struct {
	IsLast     bool
	Number     uint8
	ProtocolId ProtocolId
	Spi        []byte
	Transforms []*SaTransform
}

const (
	MIN_LEN_PROPOSAL = 8
)

func (prop *SaProposal) IsSpiSizeCorrect(spiSize int) bool {
	switch prop.ProtocolId {
	case IKE:
		if spiSize == 8 {
			return true
		}
	case ESP, AH:
		if spiSize == 4 {
			return true
		}
	}
	return false
}

func decodeProposal(b []byte) (prop *SaProposal, used int, err error) {
	if len(b) < MIN_LEN_PROPOSAL {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	prop = &SaProposal{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		prop.IsLast = true
	}
	propLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(propLength) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if int(propLength) < MIN_LEN_PROPOSAL {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	prop.Number, _ = packets.ReadB8(b, 4)
	pId, _ := packets.ReadB8(b, 5)
	prop.ProtocolId = ProtocolId(pId)
	spiSize, _ := packets.ReadB8(b, 6)
	// variable parts
	if len(b) < MIN_LEN_PROPOSAL+int(spiSize) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	numTransforms, _ := packets.ReadB8(b, 7)
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
				log.V(LOG_CODEC_ERR).Info("")
				err = ERR_INVALID_SYNTAX
				return
			}
			break
		}
	}
	if len(prop.Transforms) != int(numTransforms) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	used = int(propLength)
	return
}
func encodeProposal(prop *SaProposal, number int, isLast bool) (b []byte) {
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
	Proposals []*SaProposal
}

func (s *SaPayload) Type() PayloadType {
	return PayloadTypeSA
}
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
				log.V(LOG_CODEC_ERR).Info("")
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
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
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

func (s *IdPayload) Type() PayloadType {
	return s.IdPayloadType
}
func (s *IdPayload) Encode() (b []byte) {
	b = []byte{uint8(s.IdType), 0, 0, 0}
	return append(b, s.Data...)
}
func (s *IdPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
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
	AuthMethod AuthMethod
	Data       []byte
}

func (s *AuthPayload) Type() PayloadType {
	return PayloadTypeAUTH
}
func (s *AuthPayload) Encode() (b []byte) {
	b = []byte{uint8(s.AuthMethod), 0, 0, 0}
	return append(b, s.Data...)
}
func (s *AuthPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	// Header has already been decoded
	authMethod, _ := packets.ReadB8(b, 0)
	s.AuthMethod = AuthMethod(authMethod)
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
	if len(b) < (16+PAYLOAD_HEADER_LENGTH) || len(b) > (256+PAYLOAD_HEADER_LENGTH) {
		log.V(LOG_CODEC_ERR).Info("")
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
	// non rfc7396
	MOBIKE_SUPPORTED                    NotificationType = 16396 //	[RFC4555]
	ADDITIONAL_IP4_ADDRESS              NotificationType = 16397 //	[RFC4555]
	ADDITIONAL_IP6_ADDRESS              NotificationType = 16398 //	[RFC4555]
	NO_ADDITIONAL_ADDRESSES             NotificationType = 16399 //	[RFC4555]
	UPDATE_SA_ADDRESSES                 NotificationType = 16400 //	[RFC4555]
	COOKIE2                             NotificationType = 16401 //	[RFC4555]
	NO_NATS_ALLOWED                     NotificationType = 16402 //	[RFC4555]
	AUTH_LIFETIME                       NotificationType = 16403 //	[RFC4478]
	MULTIPLE_AUTH_SUPPORTED             NotificationType = 16404 //	[RFC4739]
	ANOTHER_AUTH_FOLLOWS                NotificationType = 16405 //	[RFC4739]
	REDIRECT_SUPPORTED                  NotificationType = 16406 //	[RFC5685]
	REDIRECT                            NotificationType = 16407 //	[RFC5685]
	REDIRECTED_FROM                     NotificationType = 16408 //	[RFC5685]
	TICKET_LT_OPAQUE                    NotificationType = 16409 //	[RFC5723]
	TICKET_REQUEST                      NotificationType = 16410 //	[RFC5723]
	TICKET_ACK                          NotificationType = 16411 //	[RFC5723]
	TICKET_NACK                         NotificationType = 16412 //	[RFC5723]
	TICKET_OPAQUE                       NotificationType = 16413 //	[RFC5723]
	LINK_ID                             NotificationType = 16414 //	[RFC5739]
	USE_WESP_MODE                       NotificationType = 16415 //	[RFC5840]
	ROHC_SUPPORTED                      NotificationType = 16416 //	[RFC5857]
	EAP_ONLY_AUTHENTICATION             NotificationType = 16417 //	[RFC5998]
	CHILDLESS_IKEV2_SUPPORTED           NotificationType = 16418 //	[RFC6023]
	QUICK_CRASH_DETECTION               NotificationType = 16419 //	[RFC6290]
	IKEV2_MESSAGE_ID_SYNC_SUPPORTED     NotificationType = 16420 //	[RFC6311]
	IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED NotificationType = 16421 //	[RFC6311]
	IKEV2_MESSAGE_ID_SYNC               NotificationType = 16422 //	[RFC6311]
	IPSEC_REPLAY_COUNTER_SYNC           NotificationType = 16423 //	[RFC6311]
	SECURE_PASSWORD_METHODS             NotificationType = 16424 //	[RFC6467]
	PSK_PERSIST                         NotificationType = 16425 //	[RFC6631]
	PSK_CONFIRM                         NotificationType = 16426 //	[RFC6631]
	ERX_SUPPORTED                       NotificationType = 16427 //	[RFC6867]
	IFOM_CAPABILITY                     NotificationType = 16428 //	[Frederic_Firmin][3GPP TS 24.303 v10.6.0 annex B.2]
	SENDER_REQUEST_ID                   NotificationType = 16429 //	[draft-yeung-g-ikev2]
	IKEV2_FRAGMENTATION_SUPPORTED       NotificationType = 16430 //	[RFC7383]
	SIGNATURE_HASH_ALGORITHMS           NotificationType = 16431 //	[RFC7427]
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
	ProtocolId          ProtocolId
	NotificationType    NotificationType
	Spi                 []byte
	Data                []byte
	NotificationMessage interface{}
}

func (s *NotifyPayload) Type() PayloadType {
	return PayloadTypeN
}
func (s *NotifyPayload) Encode() (b []byte) {
	b = []byte{uint8(s.ProtocolId), uint8(len(s.Spi) + len(s.Data)), 0, 0}
	packets.WriteB16(b, 2, uint16(s.NotificationType))
	b = append(b, s.Spi...)
	b = append(b, s.Data...)
	return
}
func (s *NotifyPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	pId, _ := packets.ReadB8(b, 0)
	s.ProtocolId = ProtocolId(pId)
	spiLen, _ := packets.ReadB8(b, 1)
	if len(b) < 4+int(spiLen) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	nType, _ := packets.ReadB16(b, 2)
	s.NotificationType = NotificationType(nType)
	s.Spi = append([]byte{}, b[4:spiLen+4]...)
	s.Data = append([]byte{}, b[spiLen+4:]...)
	switch s.NotificationType {
	case AUTH_LIFETIME:
		if ltime, errc := packets.ReadB32(s.Data, 0); errc != nil {
			log.V(LOG_CODEC_ERR).Info("")
			err = ERR_INVALID_SYNTAX
			return
		} else {
			s.NotificationMessage = time.Second * time.Duration(ltime)
		}
	}

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
	ProtocolId ProtocolId
	Spis       []Spi
}

func (s *DeletePayload) Type() PayloadType {
	return PayloadTypeD
}
func (s *DeletePayload) Encode() (b []byte) {
	b = []byte{uint8(s.ProtocolId), 0, 0, 0}
	nspi := len(s.Spis)
	if nspi > 0 {
		packets.WriteB8(b, 1, uint8(len(s.Spis[0])))
		for _, spi := range s.Spis {
			b = append(b, spi...)
		}
	}
	packets.WriteB16(b, 2, uint16(nspi))
	return
}
func (s *DeletePayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	pid, _ := packets.ReadB8(b, 0)
	s.ProtocolId = ProtocolId(pid)
	lspi, _ := packets.ReadB8(b, 1)
	nspi, _ := packets.ReadB16(b, 2)
	b = b[4:]
	if len(b) < (int(lspi) * int(nspi)) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	for i := 0; i < int(nspi); i++ {
		spi := append([]byte{}, b[:int(lspi)]...)
		s.Spis = append(s.Spis, spi)
		b = b[:int(lspi)]
	}
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
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	stype, _ := packets.ReadB8(b, 0)
	id, _ := packets.ReadB8(b, 1)
	slen, _ := packets.ReadB16(b, 2)
	if len(b) < int(slen) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	sport, _ := packets.ReadB16(b, 4)
	eport, _ := packets.ReadB16(b, 6)
	iplen := net.IPv4len
	if SelectorType(stype) == TS_IPV6_ADDR_RANGE {
		iplen = net.IPv6len
	}
	if len(b) < 8+2*iplen {
		log.V(LOG_CODEC_ERR).Info("")
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

func (s *TrafficSelectorPayload) Type() PayloadType {
	return s.TrafficSelectorPayloadType
}
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
		log.V(LOG_CODEC_ERR).Info("")
		return
	}
	numSel, _ := packets.ReadB8(b, 0)
	b = b[4:]
	for len(b) > 0 {
		sel, used, serr := decodeSelector(b)
		if serr != nil {
			err = serr
			return
		}
		s.Selectors = append(s.Selectors, sel)
		b = b[used:]
		if len(s.Selectors) != int(numSel) {
			err = ERR_INVALID_SYNTAX
			log.V(LOG_CODEC_ERR).Info("")
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
type EncryptedPayload struct {
	*PayloadHeader
}

func (s *EncryptedPayload) Type() PayloadType  { return PayloadTypeSK }
func (s *EncryptedPayload) Encode() (b []byte) { return }
func (s *EncryptedPayload) Decode(b []byte) (err error) {
	return
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

// Payloads
type Payloads struct {
	Array []Payload
}

func MakePayloads() *Payloads {
	return &Payloads{}
}
func (p *Payloads) Get(t PayloadType) Payload {
	for _, pl := range p.Array {
		if pl.Type() == t {
			return pl
		}
	}
	return nil
}
func (p *Payloads) Add(t Payload) {
	p.Array = append(p.Array, t)
}
func (p *Payloads) GetNotifications() (ns []*NotifyPayload) {
	for _, pl := range p.Array {
		if pl.Type() == PayloadTypeN {
			ns = append(ns, pl.(*NotifyPayload))
		}
	}
	return
}

func DecodePayloads(b []byte, nextPayload PayloadType) (payloads *Payloads, err error) {
	payloads = MakePayloads()
	for nextPayload != PayloadTypeNone {
		if len(b) < PAYLOAD_HEADER_LENGTH {
			log.V(LOG_CODEC_ERR).Info("")
			err = ERR_INVALID_SYNTAX
			return
		}
		pHeader := &PayloadHeader{}
		if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
			return
		}
		if len(b) < int(pHeader.PayloadLength) {
			log.V(LOG_CODEC_ERR).Info("")
			err = ERR_INVALID_SYNTAX
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
		case PayloadTypeSK:
			payload = &EncryptedPayload{PayloadHeader: pHeader}
		case PayloadTypeCP:
			payload = &ConfigurationPayload{PayloadHeader: pHeader}
		case PayloadTypeEAP:
			payload = &EapPayload{PayloadHeader: pHeader}
		}
		pbuf := b[PAYLOAD_HEADER_LENGTH:pHeader.PayloadLength]
		if err = payload.Decode(pbuf); err != nil {
			return
		}
		if log.V(LOG_CODEC) {
			js, _ := json.Marshal(payload)
			log.Infof("Payload %s: %s from:\n%s", payload.Type(), js, hex.Dump(pbuf))
		}
		payloads.Add(payload)
		if nextPayload == PayloadTypeSK {
			// log.V(1).Infof("Received %s: encrypted payloads %s", s.IkeHeader.ExchangeType, *payloads)
			return
		}
		nextPayload = pHeader.NextPayload
		b = b[pHeader.PayloadLength:]
	}
	if len(b) > 0 {
		log.V(LOG_CODEC_ERR).Infof("remaining %d\n%s", len(b), hex.Dump(b))
		err = ERR_INVALID_SYNTAX
	}
	return
}

func EncodePayloads(payloads *Payloads) (b []byte) {
	for idx, pl := range payloads.Array {
		body := pl.Encode()
		hdr := pl.Header()
		hdr.PayloadLength = uint16(len(body))
		next := PayloadTypeNone
		if idx < len(payloads.Array)-1 {
			next = payloads.Array[idx+1].Type()
		}
		hdr.NextPayload = next
		body = append(hdr.Encode(), body...)
		if log.V(LOG_CODEC) {
			js, _ := json.Marshal(pl)
			log.Infof("Payload %s: %s to:\n%s", pl.Type(), js, hex.Dump(body))
		}
		b = append(b, body...)
	}
	return
}
