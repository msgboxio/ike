package ike

import (
	"bytes"
	"net"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestOsxV6(t *testing.T) {
	if !(runtime.GOOS == "darwin") {
		t.Skip()
	}
	if checkV4onX(":80") {
		t.Error("1")
	}
	if !checkV4onX("0.0.0.0:80") {
		t.Error("2")
	}
	if !checkV4onX("localhost:80") {
		t.Error("3")
	}
	if checkV4onX("[::1]:80") {
		t.Error("4")
	}
}

type mockConn struct {
	ch chan []byte
}

func (m *mockConn) ReadPacket() (b []byte, remoteAddr, localAddr net.Addr, err error) {
	return <-m.ch, &net.UDPAddr{}, &net.UDPAddr{}, nil
}
func (m *mockConn) WritePacket(reply []byte, remoteAddr net.Addr) error {
	copy := append([]byte{}, reply...)
	m.ch <- copy
	return nil
}
func (m *mockConn) Inner() net.Conn {
	return nil
}
func (m *mockConn) Close() error {
	close(m.ch)
	return nil
}

func testConn() *mockConn {
	return &mockConn{ch: make(chan []byte, 2)}
}

func testCfg() *Config {
	cfg := DefaultConfig()
	cfg.LocalID = pskTestID
	cfg.RemoteID = pskTestID
	return cfg
}

func TestReadFragment(t *testing.T) {
	conn := testConn()
	sess, _ := NewInitiator(testCfg(), nil, conn, &SessionCallback{}, logger)
	msg, _ := InitFromSession(sess).Encode(nil, false, sess.Logger)
	conn.WritePacket(msg[:40], nil)
	conn.WritePacket(msg[40:], nil)
	m2, _ := ReadMessage(conn, sess.Logger)
	msg2, _ := m2.Encode(sess.tkm, false, sess.Logger)
	if !bytes.Equal(msg, msg2) {
		spew.Dump(msg)
		spew.Dump(msg2)
		t.Fail()
	}
}
