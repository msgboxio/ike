package ike

import (
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
)

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(parent context.Context, localID, remoteID Identity, cfg *Config, initI *Message) (*Session, error) {
	cs, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		return nil, err
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp)
	if err != nil {
		return nil, err
	}
	// cast is safe since we already checked for presence of payloads
	noI := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	ikeSpiI, err := getPeerSpi(initI, protocol.IKE)
	if err != nil {
		return nil, err
	}
	// creating tkm is expensive, should come after checks are positive
	tkm, err := NewTkmResponder(cs, espSuite, noI.Nonce)
	if err != nil {
		return nil, err
	}

	cxt, cancel := context.WithCancel(parent)

	o := &Session{
		Context:           cxt,
		cancel:            cancel,
		tkm:               tkm,
		cfg:               CopyConfig(cfg),
		IkeSpiI:           ikeSpiI,
		IkeSpiR:           MakeSpi(),
		EspSpiR:           MakeSpi()[:4],
		incoming:          make(chan *Message, 10),
		outgoing:          make(chan *OutgoingMessge, 10),
		rfc7427Signatures: true,
	}

	o.authLocal = NewAuthenticator(localID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.authRemote = NewAuthenticator(remoteID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.Fsm = state.NewFsm(state.ResponderTransitions(o), state.CommonTransitions(o))
	o.PostEvent(&state.StateEvent{Event: state.SMI_START})
	return o, nil
}
