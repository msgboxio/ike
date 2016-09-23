package ike

import (
	"net"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

func NewInitiator(parent context.Context, localId, remoteId Identity, remote net.IP, cfg *Config) *Session {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		log.Error(err)
		return nil
	}

	tkm, err := NewTkmInitiator(suite)
	if err != nil {
		log.Error(err)
		return nil
	}

	cxt, cancel := context.WithCancel(parent)

	o := &Session{
		Context:  cxt,
		cancel:   cancel,
		tkm:      tkm,
		cfg:      cfg,
		idLocal:  localId,
		idRemote: remoteId,
		remote:   remote,
		// local:    local,
		IkeSpiI:           MakeSpi(),
		EspSpiI:           MakeSpi()[:4],
		incoming:          make(chan *Message, 10),
		outgoing:          make(chan []byte, 10),
		rfc7427Signatures: true,
	}

	o.Fsm = state.NewFsm(state.InitiatorTransitions(o), state.CommonTransitions(o))
	o.PostEvent(state.StateEvent{Event: state.SMI_START})
	return o
}
