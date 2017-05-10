package protocol

import "net"

type PolicyParams struct {
	Ini, Res         net.IP // tunnel endpoints
	IniPort, ResPort int
	IniNet, ResNet   *net.IPNet
	IsTransportMode  bool
}
