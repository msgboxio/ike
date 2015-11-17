package crypto

import (
	"encoding/json"
	"fmt"

	"msgbox.io/ike/protocol"
	"msgbox.io/log"
)

type Cipher interface {
	Overhead(clear []byte) int
	VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error)
	EncryptMac(headers, payload, skA, skE []byte) (b []byte, err error)
}

type CipherSuite struct {
	Cipher // aead or nonAead

	PrfLen int
	Prf    prfFunc

	DhGroup *dhGroup

	// Lengths, in bytes, of the key material needed for each component.
	KeyLen, MacKeyLen int
}

// TODO - check that the entire suite makes sense
func NewCipherSuite(trs []*protocol.SaTransform) (*CipherSuite, error) {
	cs := &CipherSuite{}
	ok := false
	// empty variables, filled in later
	var aead *aeadCipher
	var cipher *simpleCipher

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
			keyLen := int(tr.KeyLength) / 8 // from attribute; in bits
			if cipher, ok = cipherTransform(tr.Transform.TransformId, keyLen, cipher); !ok {
				if aead, ok = aeadTransform(tr.Transform.TransformId, keyLen, aead); !ok {
					return nil, fmt.Errorf("Unsupported cipher transfom %s", tr.Transform.TransformId)
				}
			}
			cs.KeyLen = keyLen // TODO - 2 places
		case protocol.TRANSFORM_TYPE_INTEG:
			if cipher, ok = integrityTransform(tr.Transform.TransformId, cipher); !ok {
				return nil, fmt.Errorf("Unsupported mac transfom %s", tr.Transform.TransformId)
			}
			cs.MacKeyLen = cipher.macKeyLen // TODO - 2 places
		default:
			return nil, fmt.Errorf("Unsupported transfom type %s", tr.Transform.Type)
		} // end switch
	} // end loop
	if cipher == nil && aead == nil {
		return nil, fmt.Errorf("cipher transfoms were not set")
	}
	if cipher != nil && aead != nil {
		return nil, fmt.Errorf("invalid cipher transfoms combination")
	}
	if cipher != nil {
		cs.Cipher = cipher
	}
	if aead != nil {
		cs.Cipher = aead
	}
	if log.V(4) {
		js, _ := json.Marshal(*cs)
		log.Infof("Using CipherSuite: %s", js)
	}
	return cs, nil
}
