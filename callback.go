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
	SendMessage(*Session, *OutgoingMessge) error
	AddSa(*Session, *platform.SaParams) error
	RemoveSa(*Session, *platform.SaParams) error
	RekeySa(*Session) error
}
