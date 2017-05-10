package ike

import (
	"net"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/platform"
)

func TestPskAuth(t *testing.T) {
	testWithIdentity(t, pskTestID, pskTestID, logger)
}

func TestCertAuth(t *testing.T) {
	localID, remoteID := certTestIds(t)
	testWithIdentity(t, localID, remoteID, logger)
}

func TestEcCertAuth(t *testing.T) {
	localID, remoteID := eccertTestIds(t)
	testWithIdentity(t, localID, remoteID, logger)
}

func BenchmarkEcCert(bt *testing.B) {
	localID, remoteID := eccertTestIds(bt)
	for n := 0; n < bt.N; n++ {
		testWithIdentity(bt, localID, remoteID, logger)
	}
}

func BenchmarkIntCert(bt *testing.B) {
	localID, remoteID := certTestIds(bt)
	for n := 0; n < bt.N; n++ {
		testWithIdentity(bt, localID, remoteID, logger)
	}
}

func testWithIdentity(t testing.TB, locid, remid Identity, log log.Logger) {
	var cfg = DefaultConfig()
	cfg.LocalID = locid
	cfg.RemoteID = remid
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddNetworkSelectors(net, net, true)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runTestInitiator(cfg, &testcb{chr, sa, cerr}, chi, logger)
	go runTestResponder(cfg, &testcb{chi, sa, cerr}, chr, logger)

	waitFor2Sa(t, sa, cerr)
}

// server, serverIP := test.SetupContainer(t, "min", 5000, 100, func() (string, error) {
// return test.RunContainer("--rm", "--privileged", "--name", "cli", "-v",
// dir+"/server:/server", "min", "/server", "-local", "0.0.0.0:500", "-v", "2", "-tunnel")
// })
