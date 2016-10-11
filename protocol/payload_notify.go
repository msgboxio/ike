package protocol

import (
	"time"

	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
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
	case SIGNATURE_HASH_ALGORITHMS:
		algos := s.NotificationMessage.([]HashAlgorithmId)
		buf := make([]byte, len(algos)*2)
		for n, alg := range algos {
			packets.WriteB16(buf, n*2, uint16(alg))
		}
		b = append(b, buf...)
	case NAT_DETECTION_DESTINATION_IP, NAT_DETECTION_SOURCE_IP:
		b = append(b, s.NotificationMessage.([]byte)...)
	default:
		if s.NotificationMessage != nil {
			b = append(b, s.NotificationMessage.([]byte)...)
		}
	}
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
	data := b[spiLen+4:]
	switch s.NotificationType {
	case AUTH_LIFETIME:
		if ltime, errc := packets.ReadB32(data, 0); errc != nil {
			log.V(LOG_CODEC_ERR).Info("")
			err = ERR_INVALID_SYNTAX
			return
		} else {
			s.NotificationMessage = time.Second * time.Duration(ltime)
		}
	case SIGNATURE_HASH_ALGORITHMS:
		// list of 16-bit hash algorithm identifiers
		if len(data)%2 != 0 {
			log.V(LOG_CODEC_ERR).Info("SIGNATURE_HASH_ALGORITHMS data is bad")
			err = ERR_INVALID_SYNTAX
			return
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
			log.V(LOG_CODEC_ERR).Infof("Bad Cookie length: %d", len(data))
			err = ERR_INVALID_SYNTAX
			return
		}
		s.NotificationMessage = append([]byte{}, data...)
	default:
		s.NotificationMessage = append([]byte{}, data...)
	}
	return
}
