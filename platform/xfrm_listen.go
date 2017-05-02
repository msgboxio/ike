// +build linux

package platform

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type ListenerCallback func(interface{})

func ListenForEvents(parent context.Context, cb ListenerCallback, log log.Logger) {
	ch := make(chan netlink.XfrmMsg, 10)
	errCh := make(chan error)
	doneCh := make(chan struct{})
	err := netlink.XfrmMonitor(ch, doneCh, errCh,
		// nl.XFRM_MSG_ACQUIRE,
		nl.XFRM_MSG_EXPIRE)
	if err != nil {
		panic(err)
	}

	log.Log("xfrm", "Started listening for xfrm messages from kernel")
	go func() {
	done:
		for {
			select {
			case <-parent.Done():
				doneCh <- struct{}{}
				break done
			case err := <-errCh:
				log.Log("xfrm", err)
			case msg := <-ch:
				cb(msg)
			}
		}
		log.Log("xfrm", "Stopped listening for xfrm messages from kernel")
		close(ch)
		close(errCh)
		close(doneCh)
	}()
	return
}
