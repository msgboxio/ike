package protocol

import (
	"math/big"
	"net"
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

type EsnTransformId uint16

const (
	ESN_NONE EsnTransformId = 0
	ESN      EsnTransformId = 1
)

type HashAlgorithmId uint16

const (
	HASH_RESERVED HashAlgorithmId = 0
	HASH_SHA1     HashAlgorithmId = 1
	HASH_SHA2_256 HashAlgorithmId = 2
	HASH_SHA2_384 HashAlgorithmId = 3
	HASH_SHA2_512 HashAlgorithmId = 4
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

// Payload is interface expected from all payloads
type Payload interface {
	Type() PayloadType
	Decode([]byte) error
	Encode() []byte
	NextPayloadType() PayloadType
	Header() *PayloadHeader
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

// payloads

// start sa payload

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                          <Proposals>                          ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type Proposals []*SaProposal
type SaPayload struct {
	*PayloadHeader
	Proposals
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
	IsLast       bool
	Number       uint8
	ProtocolId   ProtocolId
	Spi          []byte
	SaTransforms []*SaTransform
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

type SaTransform struct {
	Transform Transform
	KeyLength uint16
	IsLast    bool
}

type Transform struct {
	Type        TransformType
	TransformId uint16
}

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

type AttributeType uint16

const (
	ATTRIBUTE_TYPE_KEY_LENGTH AttributeType = 14
)

const (
	MIN_LEN_ATTRIBUTE = 4
)

const (
	MIN_LEN_TRANSFORM = 8
)

const (
	MIN_LEN_PROPOSAL = 8
)

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

type CertEncodingType uint8

// rfc7296 section 3.6
const (
	PKCS_7_WRAPPED_X_509_CERTIFICATE CertEncodingType = 1 // UNSPECIFIED
	PGP_CERTIFICATE                  CertEncodingType = 2 // UNSPECIFIED
	DNS_SIGNED_KEY                   CertEncodingType = 3 // UNSPECIFIED
	X_509_CERTIFICATE_SIGNATURE      CertEncodingType = 4
	KERBEROS_TOKEN                   CertEncodingType = 6 // UNSPECIFIED
	CERTIFICATE_REVOCATION_LIST      CertEncodingType = 7
	AUTHORITY_REVOCATION_LIST        CertEncodingType = 8  // UNSPECIFIED
	SPKI_CERTIFICATE                 CertEncodingType = 9  // UNSPECIFIED
	X_509_CERTIFICATE_ATTRIBUTE      CertEncodingType = 10 // UNSPECIFIED
	RAW_RSA_KEY                      CertEncodingType = 11 // DEPRECATED
	HASH_URL_OF_X_509_CERTIFICATE    CertEncodingType = 12
	HASH_URL_OF_X_509_BUNDLE         CertEncodingType = 13
)

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
	CertEncodingType
	Data []byte
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
	AUTH_RSA_DIGITAL_SIGNATURE             AuthMethod = 1
	AUTH_SHARED_KEY_MESSAGE_INTEGRITY_CODE AuthMethod = 2
	AUTH_DSS_DIGITAL_SIGNATURE             AuthMethod = 3
	AUTH_ECDSA_256                         AuthMethod = 9  // RFC4754
	AUTH_ECDSA_384                         AuthMethod = 10 // RFC4754
	AUTH_ECDSA_521                         AuthMethod = 11 // RFC4754
	AUTH_DIGITAL_SIGNATURE                 AuthMethod = 14 // RFC7427
)

type AuthPayload struct {
	*PayloadHeader
	AuthMethod AuthMethod
	Data       []byte
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | ASN.1 Length  | AlgorithmIdentifier ASN.1 object              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~        AlgorithmIdentifier ASN.1 object continuing            ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Signature Value                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type SignatureAuth struct {
	Asn1Data  []byte
	Signature []byte
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
	NotificationMessage interface{}
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

// end of traffic selector

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
	ConfigurationType
	ConfigurationAttributes []ConfigurationAttribute
}

type ConfigurationType uint8

const (
	CFG_REQUEST ConfigurationType = 1
	CFG_REPLY   ConfigurationType = 2
	CFG_SET     ConfigurationType = 3
	CFG_ACK     ConfigurationType = 4
)

type ConfigurationAttributeType uint16

const (
	// Attribute Type           										Value  Multi-Valued  Length
	INTERNAL_IP4_ADDRESS ConfigurationAttributeType = 1  //     YES*          0 or 4 octets
	INTERNAL_IP4_NETMASK ConfigurationAttributeType = 2  //     NO            0 or 4 octets
	INTERNAL_IP4_DNS     ConfigurationAttributeType = 3  //     YES           0 or 4 octets
	INTERNAL_IP4_NBNS    ConfigurationAttributeType = 4  //     YES           0 or 4 octets
	INTERNAL_IP4_DHCP    ConfigurationAttributeType = 6  //     YES           0 or 4 octets
	APPLICATION_VERSION  ConfigurationAttributeType = 7  //     NO            0 or more
	INTERNAL_IP6_ADDRESS ConfigurationAttributeType = 8  //     YES*          0 or 17 octets
	INTERNAL_IP6_DNS     ConfigurationAttributeType = 10 //    YES           0 or 16 octets
	INTERNAL_IP6_DHCP    ConfigurationAttributeType = 12 //    YES           0 or 16 octets
	INTERNAL_IP4_SUBNET  ConfigurationAttributeType = 13 //    YES           0 or 8 octets
	SUPPORTED_ATTRIBUTES ConfigurationAttributeType = 14 //    NO            Multiple of 2
	INTERNAL_IP6_SUBNET  ConfigurationAttributeType = 15 //    YES           17 octets
)

/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |R|         Attribute Type      |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                             Value                             ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type ConfigurationAttribute struct {
	ConfigurationAttributeType
	Value []byte
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
