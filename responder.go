package ike

import (
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/ike/state"
	"github.com/msgboxio/log"
)

// NewResponder creates a Responder session if incoming message looks OK
func NewResponder(parent context.Context, localID, remoteID Identity, cfg *Config, initI *Message) (*Session, error) {
	if err := initI.EnsurePayloads(InitPayloads); err != nil {
		return nil, err
	}
	if err := cfg.CheckFromInit(initI); err != nil {
		return nil, err
	}
	// TODO - check if config is usable
	// check if transforms are usable
	keI := initI.Payloads.Get(protocol.PayloadTypeKE).(*protocol.KePayload)
	// make sure dh tranform id is the one that was accepted
	tr := cfg.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
	if dh := protocol.DhTransformId(tr); dh != keI.DhTransformId {
		log.Warningf("Using different DH transform [%s] vs the one configured [%s]",
			keI.DhTransformId, dh)
		return nil, protocol.ERR_INVALID_KE_PAYLOAD
	}
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
		remote:            initI.RemoteAddr,
		local:             initI.LocalAddr,
		tkm:               tkm,
		cfg:               CopyConfig(cfg),
		IkeSpiI:           ikeSpiI,
		IkeSpiR:           MakeSpi(),
		EspSpiR:           MakeSpi()[:4],
		incoming:          make(chan *Message, 10),
		outgoing:          make(chan []byte, 10),
		rfc7427Signatures: true,
	}

	o.authLocal = NewAuthenticator(localID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.authRemote = NewAuthenticator(remoteID, o.tkm, o.rfc7427Signatures, o.isInitiator)
	o.Fsm = state.NewFsm(state.ResponderTransitions(o), state.CommonTransitions(o))
	o.PostEvent(state.StateEvent{Event: state.SMI_START})
	return o, nil
}
