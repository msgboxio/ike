package ike

import (
	"net"
	"reflect"
	"testing"
)

func TestCopyConfig(t *testing.T) {
	def := DefaultConfig()
	copy := *def
	_, ipnet, _ := net.ParseCIDR("10.0.0.10/24")
	copy.AddSelector(ipnet, ipnet)
	if reflect.DeepEqual(def.TsI, copy.TsI) {
		t.FailNow()
	}
}
