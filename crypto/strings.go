package crypto

import (
	"fmt"
	"reflect"
)

func _str(name string, data interface{}) string {
	if data == nil || reflect.ValueOf(data).IsNil() {
		return ""
	}
	return fmt.Sprintf("%s:%s", name, data)
}

func (cs *CipherSuite) String() string {
	return fmt.Sprintf("%s %s %s", _str("Cipher", cs.Cipher), _str("Prf", cs.Prf), _str("DhGroup", cs.DhGroup))
}
