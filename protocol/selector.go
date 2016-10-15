package protocol

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func decodeSelector(b []byte) (sel *Selector, used int, err error) {
	if len(b) < MIN_LEN_SELECTOR {
		err = errors.Wrap(ERR_INVALID_SYNTAX, "Selector length")
		return
	}
	stype, _ := packets.ReadB8(b, 0)
	id, _ := packets.ReadB8(b, 1)
	slen, _ := packets.ReadB16(b, 2)
	if len(b) < int(slen) {
		err = errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("bad selector length\n%s", hex.Dump(b)))
		return
	}
	sport, _ := packets.ReadB16(b, 4)
	eport, _ := packets.ReadB16(b, 6)
	iplen := net.IPv4len
	if SelectorType(stype) == TS_IPV6_ADDR_RANGE {
		iplen = net.IPv6len
	}
	if len(b) < 8+2*iplen {
		err = errors.Wrap(ERR_INVALID_SYNTAX, "Selector length")
		return
	}
	sel = &Selector{
		Type:         SelectorType(stype),
		IpProtocolId: id,
		StartPort:    sport,
		Endport:      eport,
		StartAddress: append([]byte{}, b[8:8+iplen]...),
		EndAddress:   append([]byte{}, b[8+iplen:8+2*iplen]...),
	}
	used = 8 + 2*iplen
	return
}

func encodeSelector(sel *Selector) (b []byte) {
	b = make([]byte, MIN_LEN_SELECTOR)
	packets.WriteB8(b, 0, uint8(sel.Type))
	packets.WriteB8(b, 1, uint8(sel.IpProtocolId))
	packets.WriteB16(b, 4, uint16(sel.StartPort))
	packets.WriteB16(b, 6, uint16(sel.Endport))
	b = append(b, sel.StartAddress...)
	b = append(b, sel.EndAddress...)
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

func (s *TrafficSelectorPayload) Type() PayloadType {
	return s.TrafficSelectorPayloadType
}
func (s *TrafficSelectorPayload) Encode() (b []byte) {
	b = []byte{uint8(len(s.Selectors)), 0, 0, 0}
	for _, sel := range s.Selectors {
		b = append(b, encodeSelector(sel)...)
	}
	return
}
func (s *TrafficSelectorPayload) Decode(b []byte) error {
	if len(b) < MIN_LEN_TRAFFIC_SELECTOR {
		return errors.Wrap(ERR_INVALID_SYNTAX, "TrafficSelector length")
	}
	numSel, _ := packets.ReadB8(b, 0)
	b = b[4:]
	for len(b) > 0 {
		sel, used, err := decodeSelector(b)
		if err != nil {
			return err
		}
		s.Selectors = append(s.Selectors, sel)
		b = b[used:]
		if len(s.Selectors) != int(numSel) {
			return errors.Wrap(ERR_INVALID_SYNTAX, "wrong number of selectors")
		}
	}
	return nil
}
