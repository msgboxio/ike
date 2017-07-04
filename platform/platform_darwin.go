package platform

import (
	"net"
	"runtime"

	"github.com/pkg/errors"
)

func GetLocalAddress(remote net.IP) (local net.IP, err error) {
	/*
		rib, _ := route.FetchRIB(0, route.RIBTypeRoute, 0)
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		for _, message := range messages {
			msgs := message.(*route.RouteMessage)
			for n, m := range msgs.Addrs {
				switch ip := m.(type) {
				case *route.Inet4Addr:
					p := net.IPv4(ip.IP[0], ip.IP[1], ip.IP[2], ip.IP[3])
					fmt.Printf("%d:%s\n", n, p)
				}
			}
			fmt.Println("")
		}
	*/
	return nil, errors.Errorf("GetLocalAddress is not supported on %s", runtime.GOOS)
}
