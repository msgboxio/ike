package ike

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sync"
)

// dhGroup is a multiplicative group suitable for implementing Diffie-Hellman key agreement.
type dhGroup struct {
	g, p *big.Int
}

func (group *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Sign() <= 0 || theirPublic.Cmp(group.p) >= 0 {
		return nil, errors.New("ssh: DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, group.p), nil
}

func (group *dhGroup) private(randSource io.Reader) (*big.Int, error) {
	return rand.Int(randSource, group.p)
}
func (group *dhGroup) public(x *big.Int) *big.Int {
	return new(big.Int).Exp(group.g, x, group.p)
}

var kexAlgoMap map[DhTransformId]*dhGroup

var dhGroup14Once sync.Once

func initDHGroup14() {
	// This is the group called diffie-hellman-group14-sha1 in RFC
	// 4253 and Oakley Group 14 in RFC 3526.
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

	kexAlgoMap[MODP_2048] = &dhGroup{
		g: new(big.Int).SetInt64(2),
		p: p,
	}
}

func init() {
	kexAlgoMap = make(map[DhTransformId]*dhGroup)
	initDHGroup14()
}
