package ike

import (
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(parent context.Context, localId, remoteID Identity, cfg *Config, initI *Message) (*Session, error) {
	if err := initI.EnsurePayloads(InitPayloads); err != nil {
		return nil, err
	}
	rcfg, err := NewConfigFromInit(initI)
	if err != nil {
		return nil, err
	}
	// TODO - check if config is usable
	// check if transforms are usable
	keI := initI.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	// make sure dh tranform id is the one that was accepted
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if uint16(keI.DhTransformId) != tr {
		log.Warningf("Using different DH transform than the one configured %s vs %s",
			tr,
			keI.DhTransformId)
	}

	// use new config
	rcfg.IsTransportMode = cfg.IsTransportMode
	cfg = rcfg

	cs, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		return nil, err
	}

	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	tkm, err := NewTkmResponder(cs, noI.Nonce)
	if err != nil {
		return nil, err
	}

	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}

	cxt, cancel := context.WithCancel(parent)

	o := &Session{
		Context:  cxt,
		cancel:   cancel,
		idLocal:  localId,
		idRemote: remoteID,
		remote:   AddrToIp(initI.RemoteAddr),
		local:    initI.LocalIp,
		tkm:      tkm,
		cfg:      cfg,
		IkeSpiI:  ikeSpiI,
		IkeSpiR:  MakeSpi(),
		EspSpiR:  MakeSpi()[:4],
		incoming: make(chan *Message, 10),
		outgoing: make(chan []byte, 10),
	}
	go run(o)

	o.fsm = state.NewFsm(state.ResponderTransitions(o), state.CommonTransitions(o))
	go o.fsm.Run()

	o.fsm.Event(state.StateEvent{Event: state.SMI_START})
	return o, nil
}
