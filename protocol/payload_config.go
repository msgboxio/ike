package protocol

import (
	"fmt"

	"github.com/msgboxio/packets"
	"github.com/pkg/errors"
)

func (s *ConfigurationPayload) Type() PayloadType  { return PayloadTypeCP }
func (s *ConfigurationPayload) Encode() (b []byte) { return }
func (s *ConfigurationPayload) Decode(b []byte) error {
	if len(b) < 4 {
		return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("payload too small %d < %d", len(b), 4))
	}
	cfgType, _ := packets.ReadB8(b, 0)
	s.ConfigurationType = ConfigurationType(cfgType)
	b = b[4:]
	for len(b) > 0 {
		if len(b) < 4 {
			return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Attribute too small %d < %d", len(b), 4))
		}
		aType, _ := packets.ReadB16(b, 0)
		aLen, _ := packets.ReadB16(b, 2)
		if len(b) < 4+int(aLen) {
			return errors.Wrap(ERR_INVALID_SYNTAX, fmt.Sprintf("Attribute value too small %d < %d", len(b), 4+int(aLen)))
		}
		switch ConfigurationAttributeType(aType) {
		case INTERNAL_IP4_ADDRESS:
		case INTERNAL_IP4_NETMASK:
		case INTERNAL_IP4_DNS:
		case INTERNAL_IP4_NBNS:
		case INTERNAL_IP4_DHCP:
		case APPLICATION_VERSION:
		case INTERNAL_IP6_ADDRESS:
		case INTERNAL_IP6_DNS:
		case INTERNAL_IP6_DHCP:
		case INTERNAL_IP4_SUBNET:
		case SUPPORTED_ATTRIBUTES:
		case INTERNAL_IP6_SUBNET:
		}
		attr := &ConfigurationAttribute{
			ConfigurationAttributeType: ConfigurationAttributeType(aType),
			Value: append([]byte{}, b[4:aLen+4]...),
		}
		s.ConfigurationAttributes = append(s.ConfigurationAttributes, attr)
		b = b[aLen+4:]
	}
	return nil
}
