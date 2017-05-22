package ike

import (
	"errors"
)

var errPeerRemovedIkeSa = errors.New("Delete IKE SA")
var errPeerRemovedEspSa = errors.New("Delete ESP SA")
