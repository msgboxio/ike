package ike

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
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

func TestReadFragment(t *testing.T) {
	conn := testConn()
	sess, _ := NewInitiator(testCfg(), nil, log.NewNopLogger())
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
