package ike

import (
	"net"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
)

func TestInit1(t *testing.T) {
	var cfg = DefaultConfig()
	cfg.ThrottleInitRequests = true
	cfg.LocalID = pskTestId
	cfg.RemoteID = pskTestId
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestInitiator(cfg, &testcb{chr, sa, cerr}, chi, log)
	go runTestResponder(cfg, &testcb{chi, sa, cerr}, chr, log)

	waitFor2Sa(t, sa, cerr)
}

// Initiator cannot handle INVALID_KE_PAYLOAD, responder can generate one
func TestInit2(t *testing.T) {
	var cfg1 = DefaultConfig()
	cfg1.LocalID = pskTestId
	cfg1.RemoteID = pskTestId
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg1.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestInitiator(cfg1, &testcb{chr, sa, cerr}, chi, log)

	log2 := log.NewLogfmtLogger(os.Stdout)
	var cfg2 = *cfg1
	cfg2.ProposalIke = protocol.IKE_AES_GCM_16_MODP3072
	go runTestResponder(&cfg2, &testcb{chi, sa, cerr}, chr, log2)
	if err := waitFor2Sa(t, sa, cerr); err != protocol.ERR_INVALID_KE_PAYLOAD {
		t.Fail()
	}
}
