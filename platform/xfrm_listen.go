// +build linux

package platform

import (
	"context"
	"syscall"

	"github.com/msgboxio/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type Listener struct {
	context.Context
	cancel context.CancelFunc
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
	cxt, cancel := context.WithCancel(parent)
	listener = &Listener{
		Context: cxt,
		cancel:  cancel,
	}

	socket, err := nl.Subscribe(syscall.NETLINK_XFRM,
		XFRMGRP_ACQUIRE,
		XFRMGRP_EXPIRE,
		XFRMGRP_SA,
		XFRMGRP_POLICY,
		XFRMGRP_REPORT,
	)
	if err != nil {
		log.Error("xfrm listener: ", err)
		listener.cancel()
		return
	}
	listener.socket = socket
	go listener.runReader()
	return
}

func (l *Listener) Close() {
	if l.socket != nil {
		l.socket.Close()
	}
	l.cancel() // NOTE : this will leak the goroutine
}

func (l *Listener) runReader() {
	log.V(2).Infoln("Started listening for xfrm messages from kernel")
done:
	for {
		select {
		case <-l.Done():
			break done
		default:
			if err := processMsg(l.socket); err != nil {
				log.Error("xfrm listen Error:", err)
				l.cancel()
			}
		}
	}
	log.V(2).Infoln("Stopped listening for xfrm messages from kernel")
}

func processMsg(nsock *nl.NetlinkSocket) error {
	msgs, err := nsock.Receive()
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		log.Error("xfrm len 0")
	}
	for _, msg := range msgs {
		// log.Infof("msg: %+v", msg)
		switch msg.Header.Type {
		case nl.XFRM_MSG_ACQUIRE:
			log.V(3).Infof("xfrm acquire: %+v", msg.Header)
		case nl.XFRM_MSG_EXPIRE:
			log.V(3).Infof("xfrm expire: %+v", msg.Header)
		case nl.XFRM_MSG_NEWPOLICY:
			policy, _ := netlink.ParseXfrmPolicy(msg.Data, netlink.FAMILY_ALL)
			log.V(3).Infof("xfrm new policy: %+v", policy)
		case nl.XFRM_MSG_DELPOLICY:
			policy, _ := netlink.ParseXfrmPolicy(msg.Data, netlink.FAMILY_ALL)
			log.V(3).Infof("xfrm delete policy: %+v", policy)
		case nl.XFRM_MSG_NEWSA:
			sa, _ := netlink.ParseXfrmState(msg.Data, netlink.FAMILY_ALL)
			log.V(3).Infof("xfrm new sa: %+v", sa)
		case nl.XFRM_MSG_DELSA:
			sa, _ := netlink.ParseXfrmState(msg.Data, netlink.FAMILY_ALL)
			log.V(3).Infof("xfrm del sa: %+v", sa)
		case nl.XFRM_MSG_REPORT:
			log.V(3).Infof("xfrm report: %+v", msg.Header)
		default:
			log.V(3).Infof("xfrm unknown type: %+v", msg.Header)
		}
	}
	return nil
}
