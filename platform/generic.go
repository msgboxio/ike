//+build !linux

package platform

import "net"

func InstallChildSa(sa *SaParams) error {
	return nil
}

func RemoveChildSa(sa *SaParams) error {
	return nil
}

func SetSocketBypas(conn net.Conn, family uint16) (err error) {
	return
}
