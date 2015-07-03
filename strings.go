package ike

import "fmt"

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

func (et IkeExchangeType) String() string {
	switch et {
	case IKE_SA_INIT:
		return "IKE_SA_INIT"
	case IKE_AUTH:
		return "IKE_AUTH"
	case CREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case INFORMATIONAL:
		return "INFORMATIONAL"
	case IKE_SESSION_RESUME:
		return "IKE_SESSION_RESUME"
	case GSA_AUTH:
		return "GSA_AUTH"
	case GSA_REGISTRATION:
		return "GSA_REGISTRATION"
	case GSA_REKEY:
		return "GSA_REKEY"
	default:
		return "Unknown"
	}
}

func (s Selector) String() string {
	return fmt.Sprintf("(%d, %d-%d, %s-%s)",
		s.IpProtocolId,
		s.StartPort,
		s.Endport,
		s.StartAddress,
		s.EndAddress)
}
