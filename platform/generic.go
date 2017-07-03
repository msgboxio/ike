//+build !linux,!darwin

package platform

import (
	"context"
	"net"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
)

func InstallPolicy(sid int32, *protocol.PolicyParams, log.Logger, bool) error {
	return nil
}
func RemovePolicy(sid int32, *protocol.PolicyParams, log.Logger, bool) error {
	return nil
}

func InstallChildSa(sid int32, *SaParams, log.Logger) error {
	return nil
}

func RemoveChildSa(sid int32, *SaParams, log.Logger) error {
	return nil
}

func SetSocketBypass(conn net.Conn) (err error) {
	return
}

func ListenForEvents(context.Context, func(interface{}), log.Logger) {
	return
}
