package ike

import (
	"encoding/json"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func (t *Tkm) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}

func (t *Tkm) MarshalJSON() ([]byte, error) {
	suite := struct {
		ESP, IKE *crypto.CipherSuite
	}{ESP: t.espSuite, IKE: t.suite}
	return json.Marshal(suite)
}

func (o *Session) String() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func (o *Session) MarshalJSON() ([]byte, error) {
	session := struct {
		INI    protocol.Spi
		RES    protocol.Spi
		Suites *Tkm
	}{
		INI:    o.IkeSpiI,
		RES:    o.IkeSpiR,
		Suites: o.tkm,
	}
	return json.Marshal(session)
}
