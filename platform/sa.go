package platform

import "net"

type SaParams struct {
	Ini, Res         net.IP // tunnel endpoints
	IniPort, ResPort int
	IniNet, ResNet   *net.IPNet

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
	IsTransportMode            bool
	IsInitiator                bool
}
