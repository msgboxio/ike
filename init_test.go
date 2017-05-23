package ike

import (
	"net"
	"testing"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

// simple initiator & responder
func TestInit(t *testing.T) {
	var cfg = testConfig()
	cfg.LocalID = pskTestID
	cfg.RemoteID = pskTestID
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddNetworkSelectors(net, net, true)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestResponder(cfg, &testcb{chi, sa, cerr}, chr, logger)
	go runTestInitiator(cfg, &testcb{chr, sa, cerr}, chi, logger)

	if err := waitFor2Sa(t, sa, cerr); err != nil {
		t.Fail()
	}
}

// test with COOKIE
func TestInit1(t *testing.T) {
	var cfg = testConfig()
	cfg.ThrottleInitRequests = true
	cfg.LocalID = pskTestID
	cfg.RemoteID = pskTestID
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddNetworkSelectors(net, net, true)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestResponder(cfg, &testcb{chi, sa, cerr}, chr, logger)
	go runTestInitiator(cfg, &testcb{chr, sa, cerr}, chi, logger)

	if err := waitFor2Sa(t, sa, cerr); err != nil {
		t.Fail()
	}
}

// Initiator cannot handle INVALID_KE_PAYLOAD, responder can generate one
func TestInit2(t *testing.T) {
	var cfg1 = testConfig()
	cfg1.ProposalIke = crypto.Aes128Sha256Ecp256
	cfg1.LocalID = pskTestID
	cfg1.RemoteID = pskTestID
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg1.AddNetworkSelectors(net, net, true)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestInitiator(cfg1, &testcb{chr, sa, cerr}, chi, logger)

	var cfg2 = *cfg1
	cfg2.ProposalIke = crypto.Aes128Sha256Modp3072
	go runTestResponder(&cfg2, &testcb{chi, sa, cerr}, chr, logger)
	if err := waitFor2Sa(t, sa, cerr); errors.Cause(err) != protocol.ERR_INVALID_KE_PAYLOAD {
		t.Error("wrong Error", err)
	}
}
