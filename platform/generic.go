//+build !linux

package platform

import (
	"context"
	"net"

	"github.com/Sirupsen/logrus"
)

func InstallChildSa(*SaParams, *logrus.Logger) error {
	return nil
}

func RemoveChildSa(*SaParams, *logrus.Logger) error {
	return nil
}

func SetSocketBypas(conn net.Conn, family uint16) (err error) {
	return
}

func ListenForEvents(context.Context, func(interface{}), *logrus.Logger) {
	return
}
