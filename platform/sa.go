package platform

import "net"

type SaParams struct {
	Src, Dst         net.IP // tunnel endpoints
	SrcPort, DstPort int
	SrcNet, DstNet   *net.IPNet

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
	IsTransportMode            bool
}
