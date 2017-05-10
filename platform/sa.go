package platform

import "github.com/msgboxio/ike/protocol"

type SaParams struct {
	*protocol.PolicyParams

	EspTransforms protocol.Transforms

	EspEi, EspAi, EspEr, EspAr []byte
	SpiI, SpiR                 int
}
