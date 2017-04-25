package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

var (
	Aes128gcm16Prfsha256Ecp256,
	Aes256gcm16Prfsha384Ecp384,
	Chacha20poly1305Prfsha256Ecp256,
	Aes128gcm16,
	Aes256gcm16,
	Chacha20poly1305 protocol.Transforms
)

func init() {
	// IKE
	Aes128gcm16Prfsha256Ecp256 = protocol.IkeTransform(
		protocol.AEAD_AES_GCM_16,
		128,
		protocol.AUTH_NONE,
		protocol.PRF_HMAC_SHA2_256,
		protocol.ECP_256)

	Aes256gcm16Prfsha384Ecp384 = protocol.IkeTransform(
		protocol.AEAD_AES_GCM_16,
		256,
		protocol.AUTH_NONE,
		protocol.PRF_HMAC_SHA2_384,
		protocol.ECP_384)

	Chacha20poly1305Prfsha256Ecp256 = protocol.IkeTransform(
		protocol.AEAD_CHACHA20_POLY1305,
		256,
		protocol.AUTH_NONE,
		protocol.PRF_HMAC_SHA2_256,
		protocol.ECP_256)

	//ESP
	Aes128gcm16 = protocol.EspTransform(
		protocol.AEAD_AES_GCM_16,
		128,
		protocol.AUTH_NONE,
		protocol.ESN_NONE)

	Aes256gcm16 = protocol.EspTransform(
		protocol.AEAD_AES_GCM_16,
		256,
		protocol.AUTH_NONE,
		protocol.ESN_NONE)

	Chacha20poly1305 = protocol.EspTransform(
		protocol.AEAD_CHACHA20_POLY1305,
		256,
		protocol.AUTH_NONE,
		protocol.ESN_NONE)

	IkeSuites["aes128gcm16-prfsha256-ecp256"] = Aes128gcm16Prfsha256Ecp256
	IkeSuites["aes256gcm16-prfsha384-ecp384"] = Aes256gcm16Prfsha384Ecp384
	IkeSuites["chacha20poly1305-prfsha256-ecp256"] = Chacha20poly1305Prfsha256Ecp256
	EspSuites["aes128gcm16"] = Aes128gcm16
	EspSuites["aes256gcm16"] = Aes256gcm16
	EspSuites["chacha20poly1305"] = Chacha20poly1305
}

func aeadTransform(cipherID uint16, keyLen int) (*aeadCipher, error) {
	id := protocol.EncrTransformId(cipherID)
	switch id {
	case protocol.AEAD_AES_GCM_16:
		// rfc5282
		// AEAD_AES_128_GCM  & AEAD_AES_256_GCM with 16 octet ICV are supproted
		// go aead implementation assumes 16 octed atag by default
		if (keyLen != 16) && (keyLen != 32) {
			return nil, errors.Errorf("Invalid Key length: %d for transfom %s", keyLen, id.String())
		}
		ae := &aeadCipher{
			aeadFunc: func(key []byte) (cipher.AEAD, error) {
				if len(key) != keyLen {
					return nil, errors.Errorf("Invalid key of length %d, expected %d", len(key), keyLen)
				}
				block, err := aes.NewCipher(key)
				if err != nil {
					return nil, err
				}
				return cipher.NewGCM(block)
			},
			blockLen:        16,
			keyLen:          keyLen,
			saltLen:         4,  // 4 octets always
			ivLen:           8,  // 3.1 The Initialization Vector (IV) MUST be eight octets.
			icvLen:          16, // overhead
			EncrTransformId: protocol.EncrTransformId(cipherID),
		}
		return ae, nil
	case protocol.AEAD_CHACHA20_POLY1305:
		// rfc7634
		if keyLen != 32 {
			return nil, errors.Errorf("Invalid Key length: %d for transfom %s", keyLen, id.String())
		}
		ae := &aeadCipher{
			aeadFunc: func(key []byte) (cipher.AEAD, error) {
				if len(key) != keyLen {
					return nil, errors.Errorf("Invalid key of length %d, expected %d", len(key), keyLen)
				}
				return chacha20poly1305.New(key)
			},
			blockLen:        4,      // it may require padding octets so as to align the buffer to an integral multiple of 4 octets.
			keyLen:          keyLen, // The encryption key is 256 bits
			saltLen:         4,      // A 32-bit Salt
			ivLen:           8,      // The Initialization Vector (IV) is 64 bits
			icvLen:          16,     // overhead
			EncrTransformId: protocol.EncrTransformId(cipherID),
		}
		return ae, nil
	}
	return nil, errors.Errorf("Unsupported transfom %s", id.String())
}
