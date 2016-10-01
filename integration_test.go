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

func testWithIdentity(t *testing.T, locid, remid Identity) {
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)

	// create initiator
	initiator := NewInitiator(context.Background(), locid, remid, remoteAddr, localAddr, cfg)
	go initiator.Run(packetWriter(chi), saInstaller(sa), saRemover)
	initI, err := DecodeMessage(<-chi)
	if err != nil {
		t.Fatal(err)
	}
	// create responder
	responder, err := NewResponder(context.Background(), locid, remid, cfg, initI)
	if err != nil {
		t.Fatal(err)
	}
	go responder.Run(packetWriter(chr), saInstaller(sa), saRemover)
	// init to responder
	responder.PostMessage(initI)
	initR, err := DecodeMessage(<-chr)
	if err != nil {
		t.Fatal(err)
	}
	// init to initiator
	SetInitiatorParameters(initiator, initR)
	initiator.PostMessage(initR)
	authI, err := DecodeMessage(<-chi)
	if err != nil {
		t.Fatal(err)
	}
	// auth to responder
	responder.PostMessage(authI)
	authR, err := DecodeMessage(<-chr)
	if err != nil {
		t.Fatal(err)
	}
	// auth to initiator
	initiator.PostMessage(authR)
	// receive the 2 sa
	sa1 := <-sa
	sa2 := <-sa
	t.Logf("sa1: %+v", *sa1)
	t.Logf("sa2: %+v", *sa2)
}

// server, serverIP := test.SetupContainer(t, "min", 5000, 100, func() (string, error) {
// return test.RunContainer("--rm", "--privileged", "--name", "cli", "-v",
// dir+"/server:/server", "min", "/server", "-local", "0.0.0.0:500", "-v", "2", "-tunnel")
// })
