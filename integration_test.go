package ike

import (
	"net"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
)

var cfg = DefaultConfig()
var localAddr, remoteAddr net.Addr
var log = logrus.StandardLogger()

func TestIntPsk(t *testing.T) {
	testWithIdentity(t, pskTestId, pskTestId, log)
}

func TestIntCert(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	localID, remoteID := certTestIds(t)
	testWithIdentity(t, localID, remoteID, log)
}

func BenchmarkIntCert(bt *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	localID, remoteID := certTestIds(bt)
	for n := 0; n < bt.N; n++ {
		testWithIdentity(bt, localID, remoteID, log)
	}
}

func testWithIdentity(t testing.TB, locid, remid Identity, log *logrus.Logger) {
	cfg.LocalID = locid
	cfg.RemoteID = remid
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)
	cerr := make(chan error, 1)

	go runInitiator(cfg, &cb{chr, sa, cerr}, chi, log)
	go runResponder(cfg, &cb{chi, sa, cerr}, chr, log)

	// receive the 2 sa
	sa1 := <-sa
	sa2 := <-sa
	t.Logf("sa1I: %v", sa1.SpiI)
	t.Logf("sa2R: %+v", sa2.SpiR)
}

// server, serverIP := test.SetupContainer(t, "min", 5000, 100, func() (string, error) {
// return test.RunContainer("--rm", "--privileged", "--name", "cli", "-v",
// dir+"/server:/server", "min", "/server", "-local", "0.0.0.0:500", "-v", "2", "-tunnel")
// })
