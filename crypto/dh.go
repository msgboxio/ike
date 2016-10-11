package crypto

import (
	"errors"
	"io"
	"math/big"
	"strings"

	"github.com/msgboxio/ike/protocol"
)

var errKeyExchange = errors.New("IKE: invalid KeyExchange message")

type dhGroup interface {
	TransformId() protocol.DhTransformId
	DiffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error)
	Generate(randSource io.Reader) (private, public *big.Int, err error)
}

var kexAlgoMap map[protocol.DhTransformId]dhGroup

func init() {
	kexAlgoMap = make(map[protocol.DhTransformId]dhGroup)
	addModpGroups(kexAlgoMap)
	addEcpGroups(kexAlgoMap)
}

func trim(grp string) string {
	mm := func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}
	return strings.Map(mm, grp)
}
