// +build linux

package platform

import (
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type ListenerCallback func(interface{})

func ListenForEvents(parent context.Context, cb ListenerCallback, log log.Logger) {
	ch := make(chan netlink.XfrmMsg, 10)
	errCh := make(chan error)
	doneCh := make(chan struct{})
	err := netlink.XfrmMonitor(ch, doneCh, errCh,
		nl.XFRM_MSG_ACQUIRE, nl.XFRM_MSG_EXPIRE, nl.XFRM_MSG_REPORT)
	if err != nil {
		panic(err)
	}

	level.Debug(log).Log("note", "Started listening for xfrm messages from kernel")
	go func() {
	done:
		for {
			select {
			case <-parent.Done():
				doneCh <- struct{}{}
				break done
			case err := <-errCh:
				log.Warn("listener", err)
				break done
			case msg := <-ch:
				switch msg.Type() {
				case nl.XFRM_MSG_EXPIRE:
					level.Debug(log).Log("expire", spew.Sdump(msg.(*netlink.XfrmMsgExpire)))
				case nl.XFRM_MSG_ACQUIRE:
				// case nl.XFRM_MSG_NEWPOLICY:
				// case nl.XFRM_MSG_DELPOLICY:
				// case nl.XFRM_MSG_NEWSA:
				// case nl.XFRM_MSG_DELSA:
				case nl.XFRM_MSG_REPORT:
				}
			}
		}
		level.Debug(log).Log("note", "Stopped listening for xfrm messages from kernel")
		close(ch)
		close(errCh)
		close(doneCh)
	}()
	return
}
