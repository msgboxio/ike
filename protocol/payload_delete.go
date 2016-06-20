package protocol

import (
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

func (s *DeletePayload) Type() PayloadType {
	return PayloadTypeD
}
func (s *DeletePayload) Encode() (b []byte) {
	b = []byte{uint8(s.ProtocolId), 0, 0, 0}
	nspi := len(s.Spis)
	if nspi > 0 {
		packets.WriteB8(b, 1, uint8(len(s.Spis[0])))
		for _, spi := range s.Spis {
			b = append(b, spi...)
		}
	}
	packets.WriteB16(b, 2, uint16(nspi))
	return
}
func (s *DeletePayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	pid, _ := packets.ReadB8(b, 0)
	s.ProtocolId = ProtocolId(pid)
	lspi, _ := packets.ReadB8(b, 1)
	nspi, _ := packets.ReadB16(b, 2)
	b = b[4:]
	if len(b) < (int(lspi) * int(nspi)) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	for i := 0; i < int(nspi); i++ {
		spi := append([]byte{}, b[:int(lspi)]...)
		s.Spis = append(s.Spis, spi)
		b = b[:int(lspi)]
	}
	return
}
