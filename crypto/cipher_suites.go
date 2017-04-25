package crypto

import (
	"github.com/go-kit/kit/log"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var DebugCrypto = false

var (
	IkeSuites = map[string]protocol.Transforms{}
	EspSuites = map[string]protocol.Transforms{}
)

// Cipher interface provides Encryption & Integrity Protection
type Cipher interface {
	Overhead(clear []byte) int
	VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error)
	EncryptMac(ike, skA, skE []byte) (b []byte, err error)
}

var _ Cipher = (*simpleCipher)(nil)
var _ Cipher = (*aeadCipher)(nil)

type CipherSuite struct {
	Cipher  // aead or nonAead
	Prf     *Prf
	DhGroup dhGroup

	// Lengths, in bytes, of the key material needed for each component.
	KeyLen, MacTruncLen int

	log.Logger
}

// Build a CipherSuite from the given transfom
// TODO - check that the entire suite makes sense
func NewCipherSuite(trs protocol.Transforms) (*CipherSuite, error) {
	cs := &CipherSuite{}
	// empty variables, filled in later
	var aead *aeadCipher
	simple := &simpleCipher{}

	for _, tr := range trs {
		switch tr.Transform.Type {
		case protocol.TRANSFORM_TYPE_DH:
			dh, ok := kexAlgoMap[protocol.DhTransformId(tr.Transform.TransformId)]
			if !ok {
				return nil, errors.Errorf("Unsupported dh transfom %d", tr.Transform.TransformId)
			}
			cs.DhGroup = dh
		case protocol.TRANSFORM_TYPE_PRF:
			// for hmac based Prf, preferred key size is size of output
			prf, err := prfTranform(tr.Transform.TransformId)
			if err != nil {
				return nil, err
			}
			cs.Prf = prf
		case protocol.TRANSFORM_TYPE_ENCR:
			keyLen := int(tr.KeyLength) / 8 // from attribute; in bits
			var ok bool
			if ok = cipherTransform(tr.Transform.TransformId, keyLen, simple); !ok {
				var err error
				if aead, err = aeadTransform(tr.Transform.TransformId, keyLen); err != nil {
					return nil, err
				}
				keyLen = aead.keyLen + aead.saltLen
			}
			cs.KeyLen = keyLen
		case protocol.TRANSFORM_TYPE_INTEG:
			var ok bool
			if ok = integrityTransform(tr.Transform.TransformId, simple); !ok {
				return nil, errors.Errorf("Unsupported mac transfom %d", tr.Transform.TransformId)
			}
			cs.MacTruncLen = simple.macTruncLen // TODO - 2 places
		case protocol.TRANSFORM_TYPE_ESN:
		// nothing
		default:
			return nil, errors.Errorf("Unsupported transfom type %d", tr.Transform.Type)
		} // end switch
	} // end loop
	if simple.cipherFunc == nil && aead == nil {
		return nil, errors.Errorf("cipher transfoms were not set")
	}
	if simple.cipherFunc != nil && aead != nil {
		return nil, errors.Errorf("invalid cipher transfoms combination")
	}
	if simple != nil {
		cs.Cipher = simple
	}
	if aead != nil {
		cs.Cipher = aead
	}
	return cs, nil
}

func (cs *CipherSuite) CheckIkeTransforms() error {
	if cs.DhGroup == nil || cs.Prf == nil {
		return errors.Errorf("invalid cipher transfoms combination")
	}
	return nil
}

func (cs *CipherSuite) CheckEspTransforms() error {
	return nil
}
