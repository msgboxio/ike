// +build linux

package platform

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/msgboxio/netlink"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink/nl"
)

const XFRM_POLICY_ALLOW = 0

// set ike in & out bypass on defautl port 500
func SetSocketBypas(conn net.Conn) error {
	fd, family, err := sysfd(conn)
	if err != nil {
		return errors.WithStack(err)
	}
	policy := nl.XfrmUserpolicyInfo{}
	policy.Action = XFRM_POLICY_ALLOW
	policy.Sel.Family = family
	sol := syscall.SOL_IP
	ipsecPolicy := syscall.IP_XFRM_POLICY
	if family == syscall.AF_INET6 {
		sol = syscall.SOL_IPV6
		ipsecPolicy = syscall.IPV6_XFRM_POLICY
	}
	err = os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsecPolicy, unsafe.Pointer(&policy), policy.Len()))
	if err != nil {
		return errors.WithStack(err)
	}
	policy.Dir = uint8(netlink.XFRM_DIR_OUT)
	return os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsecPolicy, unsafe.Pointer(&policy), policy.Len()))
}
