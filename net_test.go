package ike

import (
	"net"
	"testing"
)

func TestIPNetToFirstAddress(t *testing.T) {
	_, n, _ := net.ParseCIDR("198.51.100.0/24")
	if IPNetToFirstAddress(n).String() != "198.51.100.0" {
		t.Fail()
	}
}

func TestIPNetToLastAddress(t *testing.T) {
	_, n, _ := net.ParseCIDR("198.51.100.0/24")
	if IPNetToLastAddress(n).String() != "198.51.100.255" {
		t.Fail()
	}
}

func TestIPNetToFirstLastAddress(t *testing.T) {
	_, n, _ := net.ParseCIDR("198.51.100.1/32")
	if IPNetToFirstAddress(n).String() != "198.51.100.1" {
		t.Fail()
	}
	if IPNetToLastAddress(n).String() != "198.51.100.1" {
		t.Fail()
	}
}

func TestFirstLastAddressToIPNet1(t *testing.T) {
	first := net.ParseIP("198.51.100.0")
	last := net.ParseIP("198.51.100.255")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "198.51.100.0/24" {
		t.Errorf("%s", out)
	}
}

func TestFirstLastAddressToIPNet2(t *testing.T) {
	first := net.ParseIP("198.51.100.1")
	last := net.ParseIP("198.51.100.1")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "198.51.100.1/32" {
		t.Errorf("%s", out)
	}
}

func TestFirstLastAddressToIPNet3(t *testing.T) {
	first := net.ParseIP("0.0.0.0")
	last := net.ParseIP("255.255.255.255")

	if out := FirstLastAddressToIPNet(first, last); out.String() != "0.0.0.0/0" {
		t.Errorf("%s", out)
	}
}
