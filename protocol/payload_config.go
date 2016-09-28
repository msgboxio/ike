package protocol

func (s *ConfigurationPayload) Type() PayloadType  { return PayloadTypeCP }
func (s *ConfigurationPayload) Encode() (b []byte) { return }
func (s *ConfigurationPayload) Decode(b []byte) (err error) {
	// TODO
	return
}
