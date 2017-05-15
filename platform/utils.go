package platform

import (
	"errors"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

// fd
func sysfd(c net.Conn) (fd int, family uint16, err error) {
	cv := reflect.ValueOf(c)
	switch ce := cv.Elem(); ce.Kind() {
	case reflect.Struct:
		netfd := ce.FieldByName("conn").FieldByName("fd")
		switch fe := netfd.Elem(); fe.Kind() {
		case reflect.Struct:
			fd = int(fe.FieldByName("sysfd").Int())
			family = uint16(fe.FieldByName("family").Int())
			return
		}
	}
	err = errors.New("invalid conn type")
	return
}

// bypass
func setsockopt(fd, level, name int, v unsafe.Pointer, l int) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(v), uintptr(l), 0); errno != 0 {
		return error(errno)
	}
	return nil
}
