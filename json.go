package ike

import (
	"encoding/json"
	"fmt"
)

func (p PayloadType) String() string {
	switch p {
	case PayloadTypeNone:
		return "None"
	case PayloadTypeSA:
		return "SA"
	case PayloadTypeKE:
		return "KE"
	case PayloadTypeIDi:
		return "IDi"
	case PayloadTypeIDr:
		return "IDr"
	case PayloadTypeCERT:
		return "CERT"
	case PayloadTypeCERTREQ:
		return "CERTREQ"
	case PayloadTypeAUTH:
		return "AUTH"
	case PayloadTypeNonce:
		return "Nonce"
	case PayloadTypeN:
		return "N"
	case PayloadTypeD:
		return "D"
	case PayloadTypeV:
		return "V"
	case PayloadTypeTSi:
		return "TSi"
	case PayloadTypeTSr:
		return "TSr"
	case PayloadTypeSK:
		return "SK"
	case PayloadTypeCP:
		return "CP"
	case PayloadTypeEAP:
		return "EAP"
	default:
		return "Unknown"
	}
}

func (p Payloads) String() string {
	var pls []PayloadType
	for _, pl := range p.Array {
		pls = append(pls, pl.Type())
	}
	return fmt.Sprintf("%v", pls)
}

func (p PayloadType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", p.String())), nil
}

type ts struct {
	PayloadType PayloadType
	Payload
}

func (p Payloads) MarshalJSON() ([]byte, error) {
	var jmap []ts
	for _, j := range p.Array {
		jmap = append(jmap, ts{j.Type(), j})
	}
	return json.Marshal(jmap)
}

func (t Transform) MarshalJSON() ([]byte, error) {
	if str, ok := transforms[t]; ok {
		return []byte(fmt.Sprintf("\"%s\"", str)), nil
	}
	return json.Marshal(t)
}
