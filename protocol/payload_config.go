package protocol

import "github.com/msgboxio/packets"

func (s *ConfigurationPayload) Type() PayloadType  { return PayloadTypeCP }
func (s *ConfigurationPayload) Encode() (b []byte) { return }
func (s *ConfigurationPayload) Decode(b []byte) (err error) {
	if len(b) < 4 {
		err = ErrF(ERR_INVALID_SYNTAX, "payload too small %d < %d", len(b), 4)
		return
	}
	cfgType, _ := packets.ReadB8(b, 0)
	s.ConfigurationType = ConfigurationType(cfgType)
	b = b[4:]
	for len(b) > 0 {
		if len(b) < 4 {
			err = ErrF(ERR_INVALID_SYNTAX, "Attribute too small %d < %d", len(b), 4)
			return
		}
		aType, _ := packets.ReadB16(b, 0)
		aLen, _ := packets.ReadB16(b, 2)
		if len(b) < 4+int(aLen) {
			err = ErrF(ERR_INVALID_SYNTAX, "Attribute value too small %d < %d", len(b), 4+int(aLen))
			return
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
	return
}
