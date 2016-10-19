package platform

import (
	"net"

	"github.com/msgboxio/ike/protocol"
)

type SaParams struct {
	Ini, Res         net.IP // tunnel endpoints
	IniPort, ResPort int
	IniNet, ResNet   *net.IPNet

	EspTransforms protocol.Transforms

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
	IsTransportMode            bool
	IsInitiator                bool
}
