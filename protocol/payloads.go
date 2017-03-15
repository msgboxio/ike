package protocol

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
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
func (p *Payloads) GetCertchain() (chain []*x509.Certificate, err error) {
	for _, pl := range p.Array {
		if pl.Type() == PayloadTypeCERT {
			certP, ok := pl.(*CertPayload)
			if !ok {
				err = errors.Errorf("unexpected payload; logic error")
				break
			}
			if certP.CertEncodingType != X_509_CERTIFICATE_SIGNATURE {
				err = errors.Errorf("cert encoding not supported: %v", certP.CertEncodingType)
				break
			}
			// cert.data is DER-encoded X.509 certificate
			x509Cert, err := x509.ParseCertificate(certP.Data)
			if err != nil {
				err = errors.Errorf("unable to parse cert: %s", err)
				break
			}
			chain = append(chain, x509Cert)
		}
	}
	if len(chain) == 0 {
		err = errors.New("Missing certificates")
	}
	return
}

func (p *Payloads) GetNotifications() (ns []*NotifyPayload) {
	for _, pl := range p.Array {
		if pl.Type() == PayloadTypeN {
			ns = append(ns, pl.(*NotifyPayload))
		}
	}
	return
}
func (p *Payloads) GetNotification(nt NotificationType) *NotifyPayload {
	for _, pl := range p.Array {
		if pl.Type() == PayloadTypeN {
			if n := pl.(*NotifyPayload); n.NotificationType == nt {
				return n
			}
		}
	}
	return nil
}

func DecodePayloads(b []byte, nextPayload PayloadType, log log.Logger) (*Payloads, error) {
	payloads := MakePayloads()
	for nextPayload != PayloadTypeNone {
		if len(b) < PAYLOAD_HEADER_LENGTH {
			return nil, errors.Wrap(ERR_INVALID_SYNTAX,
				fmt.Sprintf("payload is too small, %d < %d", len(b), PAYLOAD_HEADER_LENGTH))
		}
		pHeader := &PayloadHeader{}
		if err := pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH], log); err != nil {
			return nil, err
		}
		if (len(b) < int(pHeader.PayloadLength)) ||
			(int(pHeader.PayloadLength) < PAYLOAD_HEADER_LENGTH) {
			return nil, errors.Wrap(ERR_INVALID_SYNTAX, "incorrect payload length in payload header")
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
			return nil, errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Invalid Payload Type received: 0x%x", nextPayload))
		}
		pbuf := b[PAYLOAD_HEADER_LENGTH:pHeader.PayloadLength]
		if err := payload.Decode(pbuf); err != nil {
			return nil, err
		}
		level.Debug(log).Log("type", payload.Type(), "pld", spew.Sdump(payload), "dump", hex.Dump(pbuf))
		payloads.Add(payload)
		if nextPayload == PayloadTypeSK {
			// log.V(1).Infof("Received %s: encrypted payloads %s", s.IkeHeader.ExchangeType, *payloads)
			return payloads, nil
		}
		nextPayload = pHeader.NextPayload
		b = b[pHeader.PayloadLength:]
	}
	if len(b) > 0 {
		return nil, errors.Wrap(ERR_INVALID_SYNTAX,
			fmt.Sprintf("remaining %d\n%s", len(b), hex.Dump(b)))
	}
	return payloads, nil
}

func EncodePayloads(payloads *Payloads, log log.Logger) (b []byte) {
	for idx, pl := range payloads.Array {
		body := pl.Encode()
		hdr := pl.Header()
		hdr.PayloadLength = uint16(len(body))
		next := PayloadTypeNone
		if idx < len(payloads.Array)-1 {
			next = payloads.Array[idx+1].Type()
		}
		hdr.NextPayload = next
		body = append(hdr.Encode(log), body...)
		level.Debug(log).Log("type", pl.Type(), "pld", spew.Sdump(pl), "dump", hex.Dump(body))
		b = append(b, body...)
	}
	return
}
