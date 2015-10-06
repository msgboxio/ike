package ike_error

import "errors"

var (
	PeerDeletedSa = errors.New("Peer Deleted Sa")
	DeletedSa     = errors.New("Deleted Sa")
)
