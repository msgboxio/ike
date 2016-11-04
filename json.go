package ike

import (
	"encoding/json"

	"github.com/msgboxio/ike/crypto"
)

func (t *Tkm) MarshalJSON() ([]byte, error) {
	suite := struct {
		ESP, IKE *crypto.CipherSuite
	}{ESP: t.espSuite, IKE: t.suite}
	return json.Marshal(suite)
}

func (o *Session) MarshalJSON() ([]byte, error) {
	session := struct {
		INI    uint64
		RES    uint64
		Suites *Tkm
	}{
		INI:    SpiToInt64(o.IkeSpiI),
		RES:    SpiToInt64(o.IkeSpiR),
		Suites: o.tkm,
	}
	return json.Marshal(session)
}
