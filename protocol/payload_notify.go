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
