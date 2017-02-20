package ike

import (
	"math/big"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/crypto"
)

func NewTkm(cfg *Config, log *logrus.Logger, ni *big.Int) (*Tkm, error) {
	suite, err := crypto.NewCipherSuite(cfg.ProposalIke, log)
	if err != nil {
		return nil, err
	}
	espSuite, err := crypto.NewCipherSuite(cfg.ProposalEsp, log)
	if err != nil {
		return nil, err
	}
	if ni != nil {
		return NewTkmResponder(suite, espSuite, ni)
	}
	return NewTkmInitiator(suite, espSuite)
}
