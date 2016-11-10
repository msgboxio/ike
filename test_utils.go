package ike

import (
	"context"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
)

var pskTestId = &PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

func certTestIds(t testing.TB) (localID, remoteID Identity) {
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

	localID = &CertIdentity{
		Certificate: certs[0],
		PrivateKey:  key,
	}
	remoteID = &CertIdentity{
		Roots: roots,
		Name:  "172.17.0.1",
	}
	return
}

type cb struct {
	writeTo chan []byte
	saTo    chan *platform.SaParams
	errTo   chan error
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
func (c *cb) Error(s *Session, err error) {
	c.errTo <- err
}

func runInitiator(cfg *Config, c *cb, readFrom chan []byte, log *logrus.Logger) {
	withCb := WithCallback(context.Background(), c)
	initiator, err := NewInitiator(withCb, cfg, log)
	if err != nil {
		c.errTo <- err
	}
	// run state machine, will send initI on given channel
	go initiator.Run()
	// wait for initR
	initR, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		c.errTo <- err
	}
	// use initR
	// process initR, send authI
	initiator.PostMessage(initR)
	// wait for auhtR
	authR, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		c.errTo <- err
	}
	// process authR
	initiator.PostMessage(authR)
}

func runResponder(cfg *Config, c *cb, readFrom chan []byte, log *logrus.Logger) {
	// wait for initI
	initI, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		c.errTo <- err
	}
	// create responder
	withCb := WithCallback(context.Background(), c)
	responder, err := NewResponder(withCb, cfg, initI, log)
	if err != nil {
		c.errTo <- err
	}
	go responder.Run()
	// initI to responder, will send initR
	responder.PostMessage(initI)
	// wait for authI
	authI, err := DecodeMessage(<-readFrom, log)
	if err != nil {
		c.errTo <- err
	}
	// authI to responder, will send authR
	responder.PostMessage(authI)
}
