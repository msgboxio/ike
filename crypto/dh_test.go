package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/msgboxio/ike/protocol"
)

// make sure interfaces are implemented
var _ dhGroup = &ecpGroup{}
var _ dhGroup = &modpGroup{}

func testKeyEx(t *testing.T, tid protocol.DhTransformId, grp dhGroup) {
	t.Log("testing:", tid)
	pvt1, pub1, err := grp.Generate(rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	pvt2, pub2, err := grp.Generate(rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	// magic
	key1, err := grp.DiffieHellman(pub2, pvt1)
	if err != nil {
		t.Error(err)
		return
	}
	key2, err := grp.DiffieHellman(pub1, pvt2)
	if err != nil {
		t.Error(err)
		return
	}
	if key1.Cmp(key2) != 0 {
		t.Error("not same")
	}
	t.Logf("keylen: %d", len(key1.Bytes())*8)
}

func TestKeyEx(t *testing.T) {
	for tid, grp := range kexAlgoMap {
		testKeyEx(t, tid, grp)
	}
}
