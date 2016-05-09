package ike

import (
	"net"
	"testing"
)

func TestNetIPNetToFirstLastAddress(t *testing.T) {
	_, n, _ := net.ParseCIDR("198.51.100.1/32")
	f, l, _ := IPNetToFirstLastAddress(n)
	if f.String() != "198.51.100.1" {
		t.Fail()
	}
	if l.String() != "198.51.100.1" {
		t.Fail()
	}
}

func TestNetFirstLastAddressToIPNet1(t *testing.T) {
	first := net.ParseIP("198.51.100.0")
	last := net.ParseIP("198.51.100.255")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "198.51.100.0/24" {
		t.Errorf("%s", out)
	}
}

func TestNetFirstLastAddressToIPNet2(t *testing.T) {
	first := net.ParseIP("198.51.100.1")
	last := net.ParseIP("198.51.100.1")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "198.51.100.1/32" {
		t.Errorf("%s", out)
	}
}

func TestNetFirstLastAddressToIPNet3(t *testing.T) {
	first := net.ParseIP("0.0.0.0")
	last := net.ParseIP("255.255.255.255")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "0.0.0.0/0" {
		t.Errorf("%s", out)
	}
}
