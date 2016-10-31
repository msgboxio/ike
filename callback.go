package ike

import (
	"context"
	"net"

	"github.com/msgboxio/ike/platform"
)

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

type OutgoingMessge struct {
	Data []byte
	net.Addr
}

type Callback interface {
	SendMessage(*OutgoingMessge) error
	AddSa(*platform.SaParams) error
	RemoveSa(*platform.SaParams) error
}

type dummy struct{}

func (*dummy) SendMessage(*OutgoingMessge) error { return nil }
func (*dummy) AddSa(*platform.SaParams) error    { return nil }
func (*dummy) RemoveSa(*platform.SaParams) error { return nil }

var dummyCb dummy
