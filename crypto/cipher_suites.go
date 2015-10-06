package crypto

import (
	"fmt"

	"msgbox.io/ike/protocol"
)

type CipherSuite struct {
	PrfLen int
	Prf    prfFunc

	DhGroup *dhGroup

	// Lengths, in bytes, of the key material needed for each component.
	KeyLen            int
	MacLen, MacKeyLen int
	IvLen             int

	Cipher cipherFunc
	Mac    macFunc
	// aead   func(key, fixedNonce []byte) cipher.AEAD
}

// assume that transforms are supported
// TODO - check that the entire sute makes sense
func NewCipherSuite(trs []*protocol.SaTransform) (*CipherSuite, error) {
	cs := &CipherSuite{}
	ok := false
	for _, tr := range trs {
		switch tr.Transform.Type {
		case protocol.TRANSFORM_TYPE_DH:
			cs.DhGroup, ok = kexAlgoMap[protocol.DhTransformId(tr.Transform.TransformId)]
			if !ok {
				return nil, fmt.Errorf("Unsupported dh transfom %s", tr.Transform.TransformId)
			}
		case protocol.TRANSFORM_TYPE_PRF:
			// for hmac based Prf, preferred key size is size of output
			cs.PrfLen, cs.Prf, ok = prfTranform(tr.Transform.TransformId)
			if !ok {
				return nil, fmt.Errorf("Unsupported Prf transfom %s", tr.Transform.TransformId)
			}
		case protocol.TRANSFORM_TYPE_ENCR:
			// for block mode ciphers, equal to block length
			cs.IvLen, cs.Cipher, ok = cipherTransform(tr.Transform.TransformId)
			if !ok {
				return nil, fmt.Errorf("Unsupported cipher transfom %s", tr.Transform.TransformId)
			}
			cs.KeyLen = int(tr.KeyLength) / 8 // from attribute; in bits; 256
		case protocol.TRANSFORM_TYPE_INTEG:
			cs.MacLen, cs.MacKeyLen, cs.Mac, ok = integrityTransform(tr.Transform.TransformId)
			if !ok {
				return nil, fmt.Errorf("Unsupported mac transfom %s", tr.Transform.TransformId)
			}
		default:
			return nil, fmt.Errorf("Unsupported transfom type %s", tr.Transform.Type)
		}
	}
	return cs, nil
}
