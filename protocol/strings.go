package protocol

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

func (n NotificationType) String() string {
	switch n {
	// errors
	case UNSUPPORTED_CRITICAL_PAYLOAD:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case INVALID_IKE_SPI:
		return "INVALID_IKE_SPI"
	case INVALID_MAJOR_VERSION:
		return "INVALID_MAJOR_VERSION"
	case INVALID_SYNTAX:
		return "INVALID_SYNTAX"
	case INVALID_MESSAGE_ID:
		return "INVALID_MESSAGE_ID"
	case INVALID_SPI:
		return "INVALID_SPI"
	case NO_PROPOSAL_CHOSEN:
		return "NO_PROPOSAL_CHOSEN"
	case INVALID_KE_PAYLOAD:
		return "INVALID_KE_PAYLOAD"
	case AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED"
	case SINGLE_PAIR_REQUIRED:
		return "SINGLE_PAIR_REQUIRED"
	case NO_ADDITIONAL_SAS:
		return "NO_ADDITIONAL_SAS"
	case INTERNAL_ADDRESS_FAILURE:
		return "INTERNAL_ADDRESS_FAILURE"
	case FAILED_CP_REQUIRED:
		return "FAILED_CP_REQUIRED"
	case TS_UNACCEPTABLE:
		return "TS_UNACCEPTABLE"
	case INVALID_SELECTORS:
		return "INVALID_SELECTORS"
	case TEMPORARY_FAILURE:
		return "TEMPORARY_FAILURE"
	case CHILD_SA_NOT_FOUND:
		return "CHILD_SA_NOT_FOUND"
	// statuses
	case INITIAL_CONTACT:
		return "INITIAL_CONTACT"
	case SET_WINDOW_SIZE:
		return "SET_WINDOW_SIZE"
	case ADDITIONAL_TS_POSSIBLE:
		return "ADDITIONAL_TS_POSSIBLE"
	case IPCOMP_SUPPORTED:
		return "IPCOMP_SUPPORTED"
	case NAT_DETECTION_SOURCE_IP:
		return "NAT_DETECTION_SOURCE_IP"
	case NAT_DETECTION_DESTINATION_IP:
		return "NAT_DETECTION_DESTINATION_IP"
	case COOKIE:
		return "COOKIE"
	case USE_TRANSPORT_MODE:
		return "USE_TRANSPORT_MODE"
	case HTTP_CERT_LOOKUP_SUPPORTED:
		return "HTTP_CERT_LOOKUP_SUPPORTED"
	case REKEY_SA:
		return "REKEY_SA"
	case ESP_TFC_PADDING_NOT_SUPPORTED:
		return "ESP_TFC_PADDING_NOT_SUPPORTED"
	case NON_FIRST_FRAGMENTS_ALSO:
		return "NON_FIRST_FRAGMENTS_ALSO"
	// non rfc7396
	case MOBIKE_SUPPORTED:
		return "MOBIKE_SUPPORTED"
	case ADDITIONAL_IP4_ADDRESS:
		return "ADDITIONAL_IP4_ADDRESS"
	case ADDITIONAL_IP6_ADDRESS:
		return "ADDITIONAL_IP6_ADDRESS"
	case NO_ADDITIONAL_ADDRESSES:
		return "NO_ADDITIONAL_ADDRESSES"
	case UPDATE_SA_ADDRESSES:
		return "UPDATE_SA_ADDRESSES"
	case COOKIE2:
		return "COOKIE2"
	case NO_NATS_ALLOWED:
		return "NO_NATS_ALLOWED"
	case AUTH_LIFETIME:
		return "AUTH_LIFETIME"
	case MULTIPLE_AUTH_SUPPORTED:
		return "MULTIPLE_AUTH_SUPPORTED"
	case ANOTHER_AUTH_FOLLOWS:
		return "ANOTHER_AUTH_FOLLOWS"
	case REDIRECT_SUPPORTED:
		return "REDIRECT_SUPPORTED"
	case REDIRECT:
		return "REDIRECT"
	case REDIRECTED_FROM:
		return "REDIRECTED_FROM"
	case TICKET_LT_OPAQUE:
		return "TICKET_LT_OPAQUE"
	case TICKET_REQUEST:
		return "TICKET_REQUEST"
	case TICKET_ACK:
		return "TICKET_ACK"
	case TICKET_NACK:
		return "TICKET_NACK"
	case TICKET_OPAQUE:
		return "TICKET_OPAQUE"
	case LINK_ID:
		return "LINK_ID"
	case USE_WESP_MODE:
		return "USE_WESP_MODE"
	case ROHC_SUPPORTED:
		return "ROHC_SUPPORTED"
	case EAP_ONLY_AUTHENTICATION:
		return "EAP_ONLY_AUTHENTICATION"
	case CHILDLESS_IKEV2_SUPPORTED:
		return "CHILDLESS_IKEV2_SUPPORTED"
	case QUICK_CRASH_DETECTION:
		return "QUICK_CRASH_DETECTION"
	case IKEV2_MESSAGE_ID_SYNC_SUPPORTED:
		return "IKEV2_MESSAGE_ID_SYNC_SUPPORTED"
	case IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED:
		return "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED"
	case IKEV2_MESSAGE_ID_SYNC:
		return "IKEV2_MESSAGE_ID_SYNC"
	case IPSEC_REPLAY_COUNTER_SYNC:
		return "IPSEC_REPLAY_COUNTER_SYNC"
	case SECURE_PASSWORD_METHODS:
		return "SECURE_PASSWORD_METHODS"
	case PSK_PERSIST:
		return "PSK_PERSIST"
	case PSK_CONFIRM:
		return "PSK_CONFIRM"
	case ERX_SUPPORTED:
		return "ERX_SUPPORTED"
	case IFOM_CAPABILITY:
		return "IFOM_CAPABILITY"
	case SENDER_REQUEST_ID:
		return "SENDER_REQUEST_ID"
	case IKEV2_FRAGMENTATION_SUPPORTED:
		return "IKEV2_FRAGMENTATION_SUPPORTED"
	case SIGNATURE_HASH_ALGORITHMS:
		return "SIGNATURE_HASH_ALGORITHMS"
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
