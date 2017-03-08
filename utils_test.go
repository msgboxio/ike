package ike

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"sync"
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

func eccertTestIds(t testing.TB) (localID, remoteID Identity) {
	cacert, cakey, err := NewECCA("TEST CA")
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := NewSignedCert(CertID{
		CommonName: "172.17.0.1",
	}, key.Public(), cacert, cakey)
	if err != nil {
		t.Fatal(err)
	}

	localID = &CertIdentity{
		Certificate: cert,
		PrivateKey:  key,
	}
	roots := x509.NewCertPool()
	roots.AddCert(cacert)
	remoteID = &CertIdentity{
		Roots: roots,
		Name:  "172.17.0.1",
	}
	return
}

type testcb struct {
	writeTo chan []byte
	saTo    chan *platform.SaParams
	errTo   chan error
}

func (c *testcb) SendMessage(s *Session, msg *OutgoingMessge) error {
	c.writeTo <- msg.Data
	return nil
}
func (c *testcb) AddSa(s *Session, sa *platform.SaParams) error {
	c.saTo <- sa
	return nil
}
func (c *testcb) RemoveSa(*Session, *platform.SaParams) error { return nil }
func (c *testcb) RekeySa(*Session) error                      { return nil }
func (c *testcb) IkeAuth(*Session, error)                     {}
func (c *testcb) Error(s *Session, err error) {
	c.errTo <- err
}
func (c *testcb) SetAddresses(local, remote net.Addr) {}

func runTestInitiator(cfg *Config, c *testcb, readFrom chan []byte, log *logrus.Logger) {
	initiator, err := NewInitiator(cfg, nil, log)
	if err != nil {
		c.errTo <- err
	}
	// run state machine, will send initI on given channel
	go RunSession(initiator)

	// wait for initR
	waitForInitR := func() *Message {
		for {
			initR, err := DecodeMessage(<-readFrom, log)
			if err != nil {
				c.errTo <- err
			}
			initP, err := parseInit(initR)
			if err != nil {
				c.errTo <- err
			}
			// check if incoming message is an acceptable Init Response
			if err := CheckInitResponseForSession(initiator, initP); err != nil {
				if ce, ok := err.(CookieError); ok {
					// let retransmission take care to sending init with cookie
					// session is always returned for CookieError
					initiator.SetCookie(ce.Cookie)
				} else {
					c.errTo <- err
				}
			} else {
				return initR
			}
		}
	}
	initR := waitForInitR()
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

func runTestResponder(cfg *Config, c *testcb, readFrom chan []byte, log *logrus.Logger) {
	waitForInitI := func() *Message {
		for {
			initI, err := DecodeMessage(<-readFrom, log)
			if err != nil {
				c.errTo <- err
			}
			initP, err := parseInit(initI)
			if err != nil {
				c.errTo <- err
			}
			// is it a IKE_SA_INIT req ?
			if err := CheckInitRequest(cfg, initP, nil); err != nil {
				// handle errors that need reply: COOKIE or DH
				if reply := InitErrorNeedsReply(initP, cfg, nil, err); reply != nil {
					data, err := EncodeMessage(reply, nil, false, log)
					if err != nil {
						c.errTo <- err
					}
					c.writeTo <- data
				} else {
					c.errTo <- err
				}
			} else {
				return initI
			}
		}
	}
	// wait for initI
	initI := waitForInitI()
	// create responder
	responder, err := NewResponder(cfg, nil, initI, log)
	if err != nil {
		c.errTo <- err
	}
	go RunSession(responder)
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

func waitFor2Sa(t testing.TB, sa chan *platform.SaParams, cerr chan error) (err error) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	cxt, cancel := context.WithCancel(context.Background())
	// receive the 2 sa
	go func() error {
		for {
			select {
			case <-cxt.Done():
				return err
			case sa1 := <-sa:
				t.Logf("sa1I: %v", sa1.SpiI)
				wg.Done()
			case sa2 := <-sa:
				t.Logf("sa2R: %+v", sa2.SpiR)
				wg.Done()
			case err = <-cerr:
				cancel()
				t.Logf("%+v", err)
				wg.Done()
				wg.Done()
			}
		}
	}()
	wg.Wait()
	return
}
