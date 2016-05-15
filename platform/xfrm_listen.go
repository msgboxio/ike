// +build linux

package platform

import (
	"syscall"

	"github.com/msgboxio/context"
	"github.com/msgboxio/log"
	"github.com/msgboxio/netlink"
)

type Listener struct {
	context.Context
	context.CancelFunc
	socket *netlink.NetlinkSocket
}

func ListenForEvents(parent context.Context) (listener *Listener) {
	listener = &Listener{}
	listener.Context, listener.CancelFunc = context.WithCancel(parent)
	var err error
	listener.socket, err = netlink.Subscribe(syscall.NETLINK_XFRM, []uint32{
	// XFRMNLGRP(ACQUIRE),
	// XFRMNLGRP(EXPIRE),
	// XFRMNLGRP(MIGRATE),
	// XFRMNLGRP(MAPPING),
	})
	if err != nil {
		log.Error("xfrm listener: ", err)
		listener.CancelFunc(err)
		return
	}
	go runReader(listener.Context, listener.CancelFunc, listener.socket)
	return
}

func (listener *Listener) Close() {
	if listener.socket != nil {
		listener.socket.Close()
	}
}

func runReader(cxt context.Context, cancel context.CancelFunc, nsock *netlink.NetlinkSocket) {
	log.Infoln("Listening for xfrm messages from kernel")
	for {
		if msg, err := nsock.Recvmsg(); err != nil {
			log.Error("xfrm Error: %v", err)
			cancel(err)
			return
		} else {
			switch msg.Header.Type {
			case netlink.XFRM_MSG_ACQUIRE:
				log.Infof("xfrm acquire: %v", msg.Header)
			case netlink.XFRM_MSG_EXPIRE:
				log.Infof("xfrm expire: %v", msg.Header)
			case netlink.XFRM_MSG_MIGRATE:
				log.Infof("xfrm migrate: %v", msg.Header)
			case netlink.XFRM_MSG_MAPPING:
				log.Infof("xfrm mapping: %v", msg.Header)
			default:
				log.Infof("xfrm unknown type: 0x%x\n", msg.Header.Type)
			}
		}
	}
}
