package crypto

import (
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

func addEcpGroups(kexAlgoMap map[protocol.DhTransformId]dhGroup) {
	kexAlgoMap[protocol.ECP_224] = &ecpGroup{
		curve:         elliptic.P224(),
		DhTransformId: protocol.ECP_224,
	}
	kexAlgoMap[protocol.ECP_256] = &ecpGroup{
		curve:         elliptic.P256(),
		DhTransformId: protocol.ECP_256,
	}
	kexAlgoMap[protocol.ECP_384] = &ecpGroup{
		curve:         elliptic.P384(),
		DhTransformId: protocol.ECP_384,
	}
	kexAlgoMap[protocol.ECP_521] = &ecpGroup{
		curve:         elliptic.P521(),
		DhTransformId: protocol.ECP_521,
	}
}

// implements dhGroup interface
type ecpGroup struct {
	curve elliptic.Curve
	protocol.DhTransformId
}

func (group *ecpGroup) String() string {
	return group.DhTransformId.String()
}

func (group *ecpGroup) TransformId() protocol.DhTransformId {
	return group.DhTransformId
}

func (group *ecpGroup) DiffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	// The Diffie-Hellman shared secret value consists of the x value of the
	// Diffie-Hellman common value.
	// stdlib marshal expects b[0] = 4
	x, y := elliptic.Unmarshal(group.curve, append([]byte{4}, theirPublic.Bytes()...))
	if x == nil {
		return nil, errors.Wrap(errKeyExchange, "Bad Curve")
	}
	if !group.curve.IsOnCurve(x, y) {
		return nil, errors.Wrap(errKeyExchange, "Curve Mismatch")
	}
	x, _ = group.curve.ScalarMult(x, y, myPrivate.Bytes())
	sharedSecret := make([]byte, (group.curve.Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(sharedSecret[len(sharedSecret)-len(xBytes):], xBytes)
	// TODO - maybe fix the big.Int conversions
	return new(big.Int).SetBytes(sharedSecret), nil
}

func (group *ecpGroup) Generate(randSource io.Reader) (private, public *big.Int, err error) {
	// The Diffie-Hellman public value is obtained by concatenating the x
	// and y values.
	var x, y *big.Int
	// private
	privateKey, x, y, err := elliptic.GenerateKey(group.curve, randSource)
	if err != nil {
		return
	}
	private = new(big.Int).SetBytes(privateKey)
	// public
	publicKey := elliptic.Marshal(group.curve, x, y)
	// stdlib marshal puts b[0] = 4
	public = new(big.Int).SetBytes(publicKey[1:])
	return
}
