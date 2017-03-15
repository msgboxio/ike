package crypto

import (
	"encoding/json"
	"fmt"
	"reflect"
)

func _str(data interface{}) string {
	if data == nil || reflect.ValueOf(data).IsNil() {
		return ""
	}
	return fmt.Sprintf("%s", data)
}

func (cs *CipherSuite) MarshalJSON() ([]byte, error) {
	suite := struct {
		Cipher  string `json:",omitempty"`
		Prf     string `json:",omitempty"`
		DhGroup string `json:",omitempty"`
	}{
		Cipher:  _str(cs.Cipher),
		Prf:     _str(cs.Prf),
		DhGroup: _str(cs.DhGroup),
	}
	return json.Marshal(suite)
}

func (cs *CipherSuite) String() string {
	return fmt.Sprintf("Cipher:%s Prf:%s DhGroup:%s", _str(cs.Cipher), _str(cs.Prf), _str(cs.DhGroup))
}
