//+build !linux,!darwin

package platform

import (
	"context"
	"net"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
)

func InstallPolicy(*protocol.PolicyParams, log.Logger, bool) error {
	return nil
}
func RemovePolicy(*protocol.PolicyParams, log.Logger, bool) error {
	return nil
}

func InstallChildSa(*SaParams, log.Logger) error {
	return nil
}

func RemoveChildSa(*SaParams, log.Logger) error {
	return nil
}

func SetSocketBypas(conn net.Conn) (err error) {
	return
}

func ListenForEvents(context.Context, func(interface{}), log.Logger) {
	return
}
