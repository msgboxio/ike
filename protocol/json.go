package protocol

import (
	"encoding/json"
	"fmt"
)

func (p ProtocolId) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", p.String())), nil
}

func (p PayloadType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", p.String())), nil
}

func (p NotificationType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", p.String())), nil
}

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

func (t Transform) MarshalJSON() ([]byte, error) {
	if str, ok := transforms[t]; ok {
		return []byte(fmt.Sprintf("\"%s\"", str)), nil
	}
	return json.Marshal(t)
}

func (p IkeExchangeType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", p.String())), nil
}
