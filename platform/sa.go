package platform

import (
	"net"

	"github.com/msgboxio/ike/protocol"
)

type PolicyParams struct {
	Ini, Res         net.IP // tunnel endpoints
	IniPort, ResPort int
	IniNet, ResNet   *net.IPNet
	IsTransportMode  bool
}

type SaParams struct {
	*PolicyParams

	EspTransforms protocol.Transforms

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
}
