package ike

import "errors"

var errPeerRemovedIkeSa = errors.New("Delete IKE SA Notification")
var errPeerRemovedEspSa = errors.New("Delete ESP SA Notification")
