package ike

import (
	"context"
	"net"
	"testing"

	"github.com/msgboxio/ike/platform"
)

var pskId = &PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

var cfg = DefaultConfig()
var localAddr, remoteAddr net.Addr

func saInstaller(ch chan *platform.SaParams) SaCallback {
	return func(sa *platform.SaParams) error {
		ch <- sa
		return nil
	}
}
func saRemover(sa *platform.SaParams) error {
	return nil
}
func packetWriter(ch chan []byte) WriteData {
	return func(reply []byte) error {
		ch <- reply
		return nil
	}
}

func TestIntPsk(t *testing.T) {
	testWithIdentity(t, pskId, pskId)
}

func TestIntCert(t *testing.T) {
	testWithCert(t)
}

func BenchmarkIntCert(b *testing.B) {
	testWithCert(b)
}

func testWithCert(t testing.TB) {
	roots, err := LoadRoot("test/cert/cacert.pem")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := LoadCerts("test/cert/hostcert.der")
	if err != nil {
		t.Fatalf("Cert: %s", err)
	}
	key, err := LoadKey("test/cert/hostkey.der")
	if err != nil {
		t.Fatalf("Key: %s", err)
	}

	localID := &CertIdentity{
		Certificate: certs[0],
		PrivateKey:  key,
	}
	remoteID := &CertIdentity{
		Roots: roots,
	}
	testWithIdentity(t, localID, remoteID)
}

func runInitiator(t testing.TB, readFrom <-chan []byte, locid, remid Identity, onSa SaCallback, writeTo WriteData) {
	initiator := NewInitiator(context.Background(), locid, remid, remoteAddr, localAddr, cfg)
	initiator.AddSaHandlers(onSa, saRemover)
	// run state machine, will send initI on given channel
	go initiator.Run(writeTo)
	// wait for initR
	initR, err := DecodeMessage(<-readFrom)
	if err != nil {
		t.Fatal(err)
	}
	// use initR
	SetInitiatorParameters(initiator, initR)
	// process initR, send authI
	initiator.PostMessage(initR)
	// wait for auhtR
	authR, err := DecodeMessage(<-readFrom)
	if err != nil {
		t.Fatal(err)
	}
	// process authR
	initiator.PostMessage(authR)
}

func runResponder(t testing.TB, readFrom <-chan []byte, locid, remid Identity, onSa SaCallback, writeTo WriteData) {
	// wait for initI
	initI, err := DecodeMessage(<-readFrom)
	if err != nil {
		t.Fatal(err)
	}
	// create responder
	responder, err := NewResponder(context.Background(), locid, remid, cfg, initI)
	if err != nil {
		t.Fatal(err)
	}
	go responder.Run(writeTo)
	responder.AddSaHandlers(onSa, saRemover)
	// initI to responder, will send initR
	responder.PostMessage(initI)
	// wait for authI
	authI, err := DecodeMessage(<-readFrom)
	if err != nil {
		t.Fatal(err)
	}
	// authI to responder, will send authR
	responder.PostMessage(authI)
}

func testWithIdentity(t testing.TB, locid, remid Identity) {
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)

	go runInitiator(t, chi, locid, remid, saInstaller(sa), packetWriter(chr))
	go runResponder(t, chr, locid, remid, saInstaller(sa), packetWriter(chi))

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
