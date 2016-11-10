package ike

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
)

var pskId = &PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

var cfg = DefaultConfig()
var localAddr, remoteAddr net.Addr

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
		Name:  "172.17.0.1",
	}
	testWithIdentity(t, localID, remoteID)
}

type cb struct {
	writeTo chan []byte
	saTo    chan *platform.SaParams
}

func (c *cb) SendMessage(s *Session, msg *OutgoingMessge) error {
	c.writeTo <- msg.Data
	return nil
}
func (c *cb) AddSa(s *Session, sa *platform.SaParams) error {
	c.saTo <- sa
	return nil
}
func (c *cb) RemoveSa(*Session, *platform.SaParams) error { return nil }
func (c *cb) RekeySa(*Session) error                      { return nil }
func (c *cb) IkeAuth(*Session, error)                     {}
func (c *cb) Error(*Session, error)                     {}

func runInitiator(t testing.TB, readFrom, writeTo chan []byte, saTo chan *platform.SaParams) {
	withCb := WithCallback(context.Background(), &cb{writeTo, saTo})
	log := logrus.StandardLogger()
	initiator, err := NewInitiator(withCb, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(initiator)
	if err != nil {
		log.Info(err)
	}
	t.Log(string(js))
	// run state machine, will send initI on given channel
	go initiator.Run()
	// wait for initR
	initR, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		t.Fatal(err)
	}
	// use initR
	// process initR, send authI
	initiator.PostMessage(initR)
	// wait for auhtR
	authR, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		t.Fatal(err)
	}
	// process authR
	initiator.PostMessage(authR)
}

func runResponder(t testing.TB, readFrom, writeTo chan []byte, saTo chan *platform.SaParams) {
	log := logrus.StandardLogger()
	// wait for initI
	initI, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		t.Fatal(err)
	}
	// create responder
	withCb := WithCallback(context.Background(), &cb{writeTo, saTo})
	responder, err := NewResponder(withCb, cfg, initI, log)
	if err != nil {
		t.Fatal(err)
	}
	go responder.Run()
	// initI to responder, will send initR
	responder.PostMessage(initI)
	// wait for authI
	authI, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		t.Fatal(err)
	}
	// authI to responder, will send authR
	responder.PostMessage(authI)
}

func testWithIdentity(t testing.TB, locid, remid Identity) {
	cfg.LocalID = locid
	cfg.RemoteID = remid
	_, net, _ := net.ParseCIDR("192.0.2.0/24")
	cfg.AddSelector(net, net)
	chi := make(chan []byte, 1)
	chr := make(chan []byte, 1)
	sa := make(chan *platform.SaParams, 1)

	go runInitiator(t, chi, chr, sa)
	go runResponder(t, chr, chi, sa)

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
