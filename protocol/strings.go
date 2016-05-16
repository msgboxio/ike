package protocol

import "fmt"

func (p ProtocolId) String() string {
	switch p {
	case IKE:
		return "IKE"
	case AH:
		return "AH"
	case ESP:
		return "ESP"
	default:
		return "Unknown"
	}
}

func (p TransformType) String() string {
	switch p {
	case TRANSFORM_TYPE_ENCR:
		return "ENCR"
	case TRANSFORM_TYPE_PRF:
		return "PRF"
	case TRANSFORM_TYPE_INTEG:
		return "INTEG"
	case TRANSFORM_TYPE_DH:
		return "DH"
	case TRANSFORM_TYPE_ESN:
		return "ESN"
	default:
		return "Unknown"
	}
}

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
		return "No"
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
	var pls []string
	for _, pl := range p.Array {
		if ty := pl.Type(); ty == PayloadTypeN {
			n := pl.(*NotifyPayload)
			pls = append(pls, fmt.Sprintf("N[%s]", n.NotificationType))
		} else {
			pls = append(pls, ty.String())
		}
	}
	return fmt.Sprintf("%v", pls)
}

func (s Selector) String() string {
	return fmt.Sprintf("(%d, %d-%d, %s-%s)",
		s.IpProtocolId,
		s.StartPort,
		s.Endport,
		s.StartAddress,
		s.EndAddress)
}
