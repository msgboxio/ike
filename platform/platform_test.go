package platform

import (
	"net"
	"testing"
)

func TestOutgoing(t *testing.T) {
	addr, _ := net.ResolveIPAddr("ip", "172.28.128.1")
	local, err := GetLocalAddress(addr.IP)
	if err != nil {
		t.Error(err)
	}
	if local.IsUnspecified() {
		t.Fail()
	}
	if !local.IsGlobalUnicast() {
		t.Fail()
	}
}
