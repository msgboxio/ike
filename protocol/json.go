package protocol

import (
	"encoding/json"
	"fmt"
)

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
	if str, ok := transformStrings[t]; ok {
		return []byte(fmt.Sprintf("\"%s\"", str)), nil
	}
	return []byte(fmt.Sprintf("\"%s: %d\"", t.Type, t.TransformId)), nil
}
