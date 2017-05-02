package ike

import (
	"encoding/json"
	"fmt"

	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/protocol"
)

func (t *Tkm) String() string {
	return fmt.Sprintf("ESP:%s IKE:%s", t.espSuite, t.suite)
}

func (t *Tkm) MarshalJSON() ([]byte, error) {
	suite := struct {
		ESP, IKE *crypto.CipherSuite
	}{ESP: t.espSuite, IKE: t.suite}
	return json.Marshal(suite)
}

func (sess *Session) MarshalJSON() ([]byte, error) {
	session := struct {
		INI    protocol.Spi
		RES    protocol.Spi
		Suites *Tkm
	}{
		INI:    sess.IkeSpiI,
		RES:    sess.IkeSpiR,
		Suites: sess.tkm,
	}
	return json.Marshal(session)
}
