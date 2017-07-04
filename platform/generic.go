//+build !linux,!darwin

package platform

import (
	"context"
	"net"

	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
	"runtime"
)

func InstallPolicy(sid int32, *protocol.PolicyParams, log.Logger, bool) error {
	return  errors.Errorf("InstallPolicy is not supported on %s", runtime.GOOS)
}
func RemovePolicy(sid int32, *protocol.PolicyParams, log.Logger, bool) error {
	return  errors.Errorf("RemovePolicy is not supported on %s", runtime.GOOS)
}

func InstallChildSa(sid int32, *SaParams, log.Logger) error {
	return  errors.Errorf("InstallChildSa is not supported on %s", runtime.GOOS)
}
func RemoveChildSa(sid int32, *SaParams, log.Logger) error {
	return  errors.Errorf("RemoveChildSa is not supported on %s", runtime.GOOS)
}

func SetSocketBypass(conn net.Conn) (err error) {
	return  errors.Errorf("SetSocketBypass is not supported on %s", runtime.GOOS)
}

func ListenForEvents(context.Context, func(interface{}), log.Logger) {
	return
}

func GetLocalAddress(remote net.IP) (local net.IP, err error) {
	return nil, errors.Errorf("GetLocalAddress is not supported on %s", runtime.GOOS)
}