package protocol

import "encoding/json"
import "fmt"

type ts struct {
	PayloadType PayloadType
	Payload
}

func (p Payloads) MarshalJSON() ([]byte, error) {
	var jmap []ts
	for _, j := range p.Array {
		jmap = append(jmap, ts{j.Type(), j})
	}
	return json.Marshal(jmap)
}

func (s Spi) String() string {
	return fmt.Sprintf("%#x", []byte(s))
}

func (s *Spi) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"0x%x\"", s)), nil
}
