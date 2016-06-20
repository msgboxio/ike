package protocol

import (
	"encoding/hex"
	"encoding/json"

	"github.com/msgboxio/log"
)

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
