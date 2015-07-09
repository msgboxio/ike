package platform

import "net"

type SaParams struct {
	Src, Dst         net.IP
	SrcPort, DstPort int
	SrcNet, DstNet   *net.IPNet

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
	IsTransportMode            bool
}
