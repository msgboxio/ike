package ike

import (
	"context"
	"net"

	"github.com/msgboxio/ike/platform"
)

type OutgoingMessge struct {
	Data []byte
}

type Callback interface {
	SetAddresses(local, remote net.Addr)
	SendMessage(*Session, *OutgoingMessge) error
	AddSa(*Session, *platform.SaParams) error
	RemoveSa(*Session, *platform.SaParams) error
	IkeAuth(*Session, error)
	Error(*Session, error)
}

type SessionCallback struct {
	AddSa    func(*Session, *platform.SaParams) error
	RemoveSa func(*Session, *platform.SaParams) error
	OnError  func(*Session, error)
}

// SessionData implements SessionCallback
type SessionData struct {
	Conn          Conn
	Local, Remote net.Addr
	Cb            SessionCallback
}

type callbackKey struct{}

func ContextCallback(ctx context.Context) Callback {
	callback, ok := ctx.Value(callbackKey{}).(Callback)
	if !ok {
		panic("missing callback")
	}
	return callback
}

func WithCallback(cxt context.Context, cb Callback) context.Context {
	if cb == nil {
		panic("invalid callback")
	}
	return context.WithValue(cxt, callbackKey{}, cb)
}

func (c *SessionData) SetAddresses(local, remote net.Addr) {
	c.Local = local
	c.Remote = remote
}

func saAddr(sa *platform.SaParams, local, remote net.Addr) {
	remoteIP := AddrToIp(remote)
	localIP := AddrToIp(local)
	sa.Ini = remoteIP
	sa.Res = localIP
	if sa.IsInitiator {
		sa.Ini = localIP
		sa.Res = remoteIP
	}
}
func (o *SessionData) SendMessage(session *Session, msg *OutgoingMessge) error {
	return o.Conn.WritePacket(msg.Data, o.Remote)
}
func (o *SessionData) IkeAuth(session *Session, err error) {
	if err == nil {
		session.Logger.Info("New IKE SA: ", session)
	} else {
		session.Logger.Warningf("IKE SA FAILED: %+v", err)
	}
}
func (o *SessionData) AddSa(session *Session, sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.AddSa(session, sa)
	session.Logger.Infof("Installed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
func (o *SessionData) RemoveSa(session *Session, sa *platform.SaParams) error {
	saAddr(sa, o.Local, o.Remote)
	err := o.Cb.RemoveSa(session, sa)
	session.Logger.Infof("Removed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
func (o *SessionData) Error(session *Session, err error) {
	o.Cb.OnError(session, err)
}
