package platform

import (
	"net"

	"github.com/vishvananda/netlink"
)

func GetLocalAddress(remote net.IP) (local net.IP, err error) {
	routes, err := netlink.RouteGet(remote)
	if err != nil {
		return nil, err
	}
	return routes[0].Src, nil
}
