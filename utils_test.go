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

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/platform"
	"github.com/pkg/errors"
)

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

func testCfg() *Config {
	cfg := DefaultConfig()
	cfg.LocalID = pskTestID
	cfg.RemoteID = pskTestID
	return cfg
}

type testcb struct {
	writeTo chan []byte
	saTo    chan *platform.SaParams
	errTo   chan error
}

func (t *testcb) ReadPacket() (b []byte, remoteAddr, localAddr net.Addr, err error) {
	return
}
func (t *testcb) WritePacket(reply []byte, remoteAddr net.Addr) error {
	t.writeTo <- reply
	return nil
}
func (t *testcb) Inner() net.Conn { return nil }
func (t *testcb) Close() error    { return nil }

func sdata(cbk *testcb) *SessionData {
	return &SessionData{
		Conn: cbk,
		Cb: SessionCallback{
			AddSa: func(_ *Session, sa *platform.SaParams) error {
				cbk.saTo <- sa
				return nil
			},
			RemoveSa: func(_ *Session, sa *platform.SaParams) error {
				return nil
			},
		},
	}
}

func runTestInitiator(cfg *Config, cbk *testcb, readFrom chan []byte, log log.Logger) {
	initiator, err := NewInitiator(cfg, sdata(cbk), log)
	if err != nil {
		cbk.errTo <- err
	}
	// run state machine, will send initI on given channel
	go func() {
		err = RunSession(initiator)
		if err != nil {
			cbk.errTo <- err
		}
	}()

	for {
		msg, err := DecodeMessage(<-readFrom, log)
		if err != nil {
			cbk.errTo <- err
			break
		}
		initiator.PostMessage(msg)
	}
}

func runTestResponder(cfg *Config, cbk *testcb, readFrom chan []byte, log log.Logger) {
	waitForInitI := func() *Message {
		for {
			initI, err := DecodeMessage(<-readFrom, log)
			if err != nil {
				cbk.errTo <- err
			}
			if err = HandleInitRequest(initI, cbk, cfg, log); errors.Cause(err) == errMissingCookie {
				continue
			} else if err != nil {
				cbk.errTo <- err
				return nil
			}
			return initI
		}
	}
	// wait for initI
	initI := waitForInitI()
	if initI == nil {
		return
	}
	// create responder
	responder, err := NewResponder(cfg, sdata(cbk), initI, log)
	if err != nil {
		cbk.errTo <- err
	}
	go func() {
		err = RunSession(responder)
		if err != nil {
			cbk.errTo <- err
		}
	}()
	// initI to responder, will send initR
	responder.PostMessage(initI)
	for {
		authI, err := DecodeMessage(<-readFrom, log)
		if err != nil {
			cbk.errTo <- err
			break
		}
		// authI to responder, will send authR
		responder.PostMessage(authI)
	}
}

func waitFor2Sa(t testing.TB, sa chan *platform.SaParams, cerr chan error) (err error) {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	cxt, cancel := context.WithCancel(context.Background())
	// receive the 2 sa
	go func() {
	done:
		for {
			select {
			case <-cxt.Done():
				t.Log("XXX DONE XXX")
				break done
			case sa1 := <-sa:
				t.Logf("sa1I: %v", sa1.SpiI)
				wg.Done()
			case sa2 := <-sa:
				t.Logf("sa2R: %+v", sa2.SpiR)
				wg.Done()
			case err = <-cerr:
				cancel()
				t.Logf("error: %+v", err)
				wg.Done()
				wg.Done()
				break done
			}
		}
	}()
	wg.Wait()
	cancel()
	return
}
