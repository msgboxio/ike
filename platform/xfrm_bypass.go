// +build linux

package platform

import (
	"errors"
	"net"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
)

// fd
func sysfd(c net.Conn) (int, error) {
	cv := reflect.ValueOf(c)
	switch ce := cv.Elem(); ce.Kind() {
	case reflect.Struct:
		netfd := ce.FieldByName("conn").FieldByName("fd")
		switch fe := netfd.Elem(); fe.Kind() {
		case reflect.Struct:
			fd := fe.FieldByName("sysfd")
			return int(fd.Int()), nil
		}
	}
	return 0, errors.New("invalid conn type")
}

// bypass
func setsockopt(fd, level, name int, v unsafe.Pointer, l int) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(l), 0); errno != 0 {
		return error(errno)
	}
	return nil
}

const XFRM_POLICY_ALLOW = 0

const (
	XFRM_POLICY_IN  uint8 = 0
	XFRM_POLICY_OUT       = 1
)

// set ike in & out bypass on defautl port 500
func SetSocketBypas(conn net.Conn, family uint16) error {
	fd, err := sysfd(conn)
	if err != nil {
		return err
	}
	policy := nl.XfrmUserpolicyInfo{}
	policy.Action = XFRM_POLICY_ALLOW
	policy.Sel.Family = family
	sol := syscall.SOL_IP
	ipsec_policy := syscall.IP_XFRM_POLICY
	if family == syscall.AF_INET6 {
		sol = syscall.SOL_IPV6
		ipsec_policy = syscall.IPV6_XFRM_POLICY
	}
	err = os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsec_policy, unsafe.Pointer(&policy), policy.Len()))
	if err != nil {
		return err
	}
	policy.Dir = XFRM_POLICY_OUT
	return os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsec_policy, unsafe.Pointer(&policy), policy.Len()))
}
