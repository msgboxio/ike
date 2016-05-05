package protocol

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

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
			log.V(LOG_CODEC_ERR).Info("payload is too small, %d < %d", len(b), PAYLOAD_HEADER_LENGTH)
			err = ERR_INVALID_SYNTAX
			return
		}
		pHeader := &PayloadHeader{}
		if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
			return
		}
		if (len(b) < int(pHeader.PayloadLength)) ||
			(int(pHeader.PayloadLength) < PAYLOAD_HEADER_LENGTH) {
			log.V(LOG_CODEC_ERR).Info("incorrect payload length in payload header")
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
		default:
			log.V(LOG_CODEC_ERR).Infof("Invalid Payload Type received: 0x%x", nextPayload)
			err = ERR_INVALID_SYNTAX
			return
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
