// +build linux

package platform

import (
	"syscall"

	"github.com/msgboxio/context"
	"github.com/msgboxio/log"
	"github.com/vishvananda/netlink/nl"
)

type Listener struct {
	context.Context
	context.CancelFunc
	socket *nl.NetlinkSocket
}

const (
	XFRMGRP_ACQUIRE uint = 1
	XFRMGRP_EXPIRE       = 2
	XFRMGRP_SA           = 3
	XFRMGRP_POLICY       = 4
	XFRMGRP_REPORT       = 10
)

func ListenForEvents(parent context.Context) (listener *Listener) {
	listener = &Listener{}
	listener.Context, listener.CancelFunc = context.WithCancel(parent)
	var err error
	listener.socket, err = nl.Subscribe(syscall.NETLINK_XFRM,
		XFRMGRP_ACQUIRE,
		XFRMGRP_EXPIRE,
		XFRMGRP_SA,
		XFRMGRP_POLICY,
		XFRMGRP_REPORT,
	)

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

func runReader(cxt context.Context, cancel context.CancelFunc, nsock *nl.NetlinkSocket) {
	log.Infoln("Listening for xfrm messages from kernel")
	for {
		if msgs, err := nsock.Receive(); err != nil {
			log.Error("xfrm Error:", err)
			cancel(err)
			return
		} else {
			for _, msg := range msgs {
				switch msg.Header.Type {
				case nl.XFRM_MSG_ACQUIRE:
					log.Infof("xfrm acquire: %v", msg.Header)
				case nl.XFRM_MSG_EXPIRE:
					log.Infof("xfrm expire: %v", msg.Header)
				case nl.XFRM_MSG_NEWPOLICY:
					log.Infof("xfrm new policy: %v", msg.Header)
				case nl.XFRM_MSG_DELPOLICY:
					log.Infof("xfrm delete policy: %v", msg.Header)
				case nl.XFRM_MSG_NEWSA:
					log.Infof("xfrm new sa: %v", msg.Header)
				case nl.XFRM_MSG_DELSA:
					log.Infof("xfrm del sa: %v", msg.Header)
				case nl.XFRM_MSG_REPORT:
					log.Infof("xfrm report: %v", msg.Header)
				default:
					log.Infof("xfrm unknown type: 0x%x\n", msg.Header.Type)
				}
			}
		}
	}
}
