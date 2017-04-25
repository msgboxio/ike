package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/msgboxio/ike/protocol"
)

func TestCipherSuite(t *testing.T) {
	// create cipher suite for all transform
	transforms := IkeSuites
	for name, trs := range transforms {
		t.Log(name)
		cs, err := NewCipherSuite(trs)
		if err != nil {
			t.Error(err)
			continue
		}
		ka := make([]byte, cs.KeyLen)
		ke := make([]byte, cs.KeyLen)
		data := make([]byte, 256)
		rand.Read(ka)
		rand.Read(ke)
		rand.Read(data)

		t.Log(cs)
		if _, ok := cs.Cipher.(*aeadCipher); ok {
			// debugCrypto = true
		}
		enc, err := cs.EncryptMac(data, ka, ke)
		if err != nil {
			t.Error(err)
		}
		// dec is the decoded payloads
		dec, err := cs.VerifyDecrypt(enc, ka, ke)
		if err != nil {
			t.Error(err)
		}
		enclen := protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH
		if bytes.Compare(data[enclen:], dec) != 0 {
			t.Error("different data:")
			t.Logf("orig:\n%s", hex.Dump(data))
			t.Logf("enc:\n%s", hex.Dump(enc))
			t.Logf("dec:\n%s", hex.Dump(dec))
		}
	}
}
