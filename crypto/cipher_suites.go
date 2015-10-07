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
	KeyLen, MacKeyLen int

	MacLen, IvLen, BlockLen int

	Cipher cipherFunc
	Mac    macFunc

	AeadFunc aeadFunc
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
			if cs.AeadFunc, ok = aeadTransform(tr.Transform.TransformId); ok {
				continue
			}
			// for block mode ciphers, equal to block length
			cs.BlockLen, cs.Cipher, ok = cipherTransform(tr.Transform.TransformId)
			if !ok {
				return nil, fmt.Errorf("Unsupported cipher transfom %s", tr.Transform.TransformId)
			}
			cs.IvLen = cs.BlockLen
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

func (cs *CipherSuite) Overhead(clear []byte) int {
	return cs.BlockLen - len(clear)%cs.BlockLen + cs.MacLen
}

// MAC-then-decrypt

func (cs *CipherSuite) verifyMac(b, key []byte) (err error) {
	return verifyMac(b, key, cs.MacLen, cs.Mac)
}

func (cs *CipherSuite) decrypt(b, key []byte) ([]byte, error) {
	return decrypt(b, key, cs.IvLen, cs.Cipher)
}

// encrypt-then-MAC

func (cs *CipherSuite) encrypt(b, key []byte) ([]byte, error) {
	return encrypt(b, key, cs.IvLen, cs.Cipher)
}

// combined ops

func (cs *CipherSuite) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	if cs.AeadFunc != nil {
		return
	}
	// 2 steps
	if err = cs.verifyMac(ike, skA); err != nil {
		return
	}
	b := ike[protocol.IKE_HEADER_LEN:]
	dec, err = cs.decrypt(b[protocol.PAYLOAD_HEADER_LENGTH:len(b)-cs.MacLen], skE)
	return
}

func (cs *CipherSuite) EncryptMac(headers, payload, skA, skE []byte) (b []byte, err error) {
	if cs.AeadFunc != nil {
		return
	}
	// 2 steps
	encr, err := cs.encrypt(payload, skE)
	if err != nil {
		return
	}
	data := append(headers, encr...)
	b = append(data, cs.Mac(data, skA)...)
	return
}
