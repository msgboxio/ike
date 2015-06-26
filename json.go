package ike

import (
	"encoding/json"
	"fmt"
)

func (p PayloadType) String() string {
	switch p {
	case PayloadTypeNone:
		return "No Next Payload"
	case PayloadTypeSA:
		return "Security Association"
	case PayloadTypeKE:
		return "Key Exchange"
	case PayloadTypeIDi:
		return "Identification - Initiator"
	case PayloadTypeIDr:
		return "Identification - Responder"
	case PayloadTypeCERT:
		return "Certificate"
	case PayloadTypeCERTREQ:
		return "Certificate Request"
	case PayloadTypeAUTH:
		return "Authentication"
	case PayloadTypeNonce:
		return "Nonce"
	case PayloadTypeN:
		return "Notify"
	case PayloadTypeD:
		return "Delete"
	case PayloadTypeV:
		return "Vendor ID"
	case PayloadTypeTSi:
		return "Traffic Selector - Initiator"
	case PayloadTypeTSr:
		return "Traffic Selector - Responder"
	case PayloadTypeSK:
		return "Encrypted and Authenticated"
	case PayloadTypeCP:
		return "Configuration"
	case PayloadTypeEAP:
		return "Extensible Authentication"
	default:
		return "Unknown"
	}
}

type ts struct {
	Type string
	Payload
}

func (p Payloads) MarshalJSON() ([]byte, error) {
	var jmap []ts
	for _, j := range p.Array {
		jmap = append(jmap, ts{j.Type().String(), j})
	}
	return json.Marshal(jmap)
}

func (t Transform) MarshalJSON() ([]byte, error) {
	if str, ok := transforms[t]; ok {
		return []byte(fmt.Sprintf("\"%s\"", str)), nil
	}
	return json.Marshal(t)
}
