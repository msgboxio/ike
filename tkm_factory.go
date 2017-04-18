package ike

import (
	"math/big"

	"github.com/msgboxio/ike/crypto"
)

func NewTkm(cfg *Config, ni *big.Int) (*Tkm, error) {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke)
	if err != nil {
		return nil, err
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp)
	if err != nil {
		return nil, err
	}
	if ni != nil {
		return NewTkmResponder(suite, espSuite, ni)
	}
	return NewTkmInitiator(suite, espSuite)
}
