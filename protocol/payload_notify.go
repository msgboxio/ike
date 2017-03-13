package protocol

import (
	"time"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (s *NotifyPayload) Type() PayloadType {
	return PayloadTypeN
}

func (s *NotifyPayload) Encode() (b []byte) {
	b = []byte{uint8(s.ProtocolId), uint8(len(s.Spi)), 0, 0}
	packets.WriteB16(b, 2, uint16(s.NotificationType))
	b = append(b, s.Spi...)
	switch s.NotificationType {
	case AUTH_LIFETIME:
		lft := s.NotificationMessage.(time.Duration)
		buf := make([]byte, 4)
		// time in seconds
		packets.WriteB32(buf, 0, uint32(lft.Seconds()))
		b = append(b, buf...)
	case SIGNATURE_HASH_ALGORITHMS:
		algos := s.NotificationMessage.([]HashAlgorithmId)
		buf := make([]byte, len(algos)*2)
		for n, alg := range algos {
			packets.WriteB16(buf, n*2, uint16(alg))
		}
		b = append(b, buf...)
	case NAT_DETECTION_DESTINATION_IP, NAT_DETECTION_SOURCE_IP:
		b = append(b, s.NotificationMessage.([]byte)...)
	case INVALID_KE_PAYLOAD:
		buf := []byte{0, 0}
		packets.WriteB16(buf, 0, s.NotificationMessage.(uint16))
		b = append(b, buf...)
	default:
		if s.NotificationMessage != nil {
			b = append(b, s.NotificationMessage.([]byte)...)
		}
	}
	return
}

func (s *NotifyPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload length")
	}
	pId, _ := packets.ReadB8(b, 0)
	s.ProtocolId = ProtocolId(pId)
	spiLen, _ := packets.ReadB8(b, 1)
	if len(b) < 4+int(spiLen) {
		return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload length")
	}
	nType, _ := packets.ReadB16(b, 2)
	s.NotificationType = NotificationType(nType)
	s.Spi = append([]byte{}, b[4:spiLen+4]...)
	data := b[spiLen+4:]
	switch s.NotificationType {
	case AUTH_LIFETIME:
		if ltime, errc := packets.ReadB32(data, 0); errc != nil {
			return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload length")
		} else {
			s.NotificationMessage = time.Second * time.Duration(ltime)
		}
	case SIGNATURE_HASH_ALGORITHMS:
		// list of 16-bit hash algorithm identifiers
		if len(data)%2 != 0 {
			return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload SIGNATURE_HASH_ALGORITHMS")
		}
		var algos []HashAlgorithmId
		numAlgs := len(data) / 2
		for i := 0; i < numAlgs; i++ {
			alg, _ := packets.ReadB16(data, i*2)
			algos = append(algos, HashAlgorithmId(alg))
		}
		s.NotificationMessage = algos
	case NAT_DETECTION_DESTINATION_IP, NAT_DETECTION_SOURCE_IP:
		s.NotificationMessage = append([]byte{}, data...)
	case COOKIE:
		// check if data is <= 64 bytes
		if len(data) == 0 || len(data) > 64 {
			return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload COOKIE")
		}
		s.NotificationMessage = append([]byte{}, data...)
	case INVALID_KE_PAYLOAD:
		// check if data is 2 bytes
		if len(data) != 2 {
			return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload INVALID_KE_PAYLOAD")
		}
		s.NotificationMessage, _ = packets.ReadB16(data, 0)
	case SET_WINDOW_SIZE:
		if len(data) != 4 {
			return errors.Wrap(ERR_INVALID_SYNTAX, "Notify payload SET_WINDOW_SIZE")
		}
		wsize, _ := packets.ReadB32(data, 0)
		s.NotificationMessage = wsize
	default:
		s.NotificationMessage = append([]byte{}, data...)
	}
	return
}
