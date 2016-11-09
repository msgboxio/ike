// +build linux

package platform

import (
	"syscall"

	"github.com/msgboxio/context"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type ListenerCallback func(interface{})

type Listener struct {
	context.Context
	cancel   context.CancelFunc
	socket   *nl.NetlinkSocket
	callback ListenerCallback
}

const (
	XFRMGRP_ACQUIRE uint = 1
	XFRMGRP_EXPIRE       = 2
	XFRMGRP_SA           = 3
	XFRMGRP_POLICY       = 4
	XFRMGRP_REPORT       = 10
)

func ListenForEvents(parent context.Context, cb ListenerCallback, log *logrus.Logger) (listener *Listener) {
	cxt, cancel := context.WithCancel(parent)
	listener = &Listener{
		Context:  cxt,
		cancel:   cancel,
		callback: cb,
	}

	socket, err := nl.Subscribe(syscall.NETLINK_XFRM,
		XFRMGRP_ACQUIRE,
		XFRMGRP_EXPIRE,
		XFRMGRP_SA,
		XFRMGRP_POLICY,
		XFRMGRP_REPORT,
	)
	if err != nil {
		listener.cancel(errors.Wrap(err, "xfrm Subscribe"))
		return
	}
	listener.socket = socket
	go listener.runReader(log)
	return
}

func (l *Listener) Close() {
	if l.socket != nil {
		l.socket.Close()
	}
	l.cancel(context.Canceled) // NOTE : this will leak the goroutine
}

func (l *Listener) runReader(log *logrus.Logger) {
	log.Debug("Started listening for xfrm messages from kernel")
done:
	for {
		select {
		case <-l.Done():
			break done
		default:
			if err := processMsg(l.socket, l.callback, log); err != nil {
				l.cancel(errors.Wrap(err, "xfrm Message"))
			}
		}
	}
	log.Debug("Stopped listening for xfrm messages from kernel")
}

func processMsg(nsock *nl.NetlinkSocket, cb ListenerCallback, log *logrus.Logger) error {
	msgs, err := nsock.Receive()
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		log.Error("xfrm len 0")
	}
	for _, msg := range msgs {
		var ret interface{}
		switch msg.Header.Type {
		case nl.XFRM_MSG_ACQUIRE:
			log.Debugf("xfrm acquire: %+v", msg.Header)
		case nl.XFRM_MSG_EXPIRE:
			log.Debugf("xfrm expire: %+v", msg.Header)
		case nl.XFRM_MSG_NEWPOLICY:
			policy, _ := netlink.ParseXfrmPolicy(msg.Data, netlink.FAMILY_ALL)
			log.Debugf("xfrm new policy: %+v", policy)
			ret = policy
		case nl.XFRM_MSG_DELPOLICY:
			policy, _ := netlink.ParseXfrmPolicy(msg.Data, netlink.FAMILY_ALL)
			log.Debugf("xfrm delete policy: %+v", policy)
			ret = policy
		case nl.XFRM_MSG_NEWSA:
			sa, _ := netlink.ParseXfrmState(msg.Data, netlink.FAMILY_ALL)
			log.Debugf("xfrm new sa: %+v", sa)
			ret = sa
		case nl.XFRM_MSG_DELSA:
			sa, _ := netlink.ParseXfrmState(msg.Data, netlink.FAMILY_ALL)
			log.Debugf("xfrm del sa: %+v", sa)
			ret = sa
		case nl.XFRM_MSG_REPORT:
			log.Debugf("xfrm report: %+v", msg.Header)
		default:
			log.Debugf("xfrm unknown type: %+v", msg.Header)
		}
		if cb != nil && ret != nil {
			cb(ret)
		}
	}
	return nil
}
