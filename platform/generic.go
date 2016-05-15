//+build !linux

package platform

import (
	"net"

	"golang.org/x/net/context"
)

func InstallChildSa(sa *SaParams) error {
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	return nil
}

func SetSocketBypas(conn net.Conn, family uint16) (err error) {
	return
}

type Listener struct {
	context.Context
}

func (Listener) Close() {}
func ListenForEvents(parent context.Context) (listener *Listener) {
	return
}
