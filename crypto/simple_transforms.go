package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/msgboxio/ike/protocol"
)

// cipherFunc Implementations

var (
	Aes128Sha256Modp3072,
	Aes128Sha256Ecp256,
	Aes128Sha256 protocol.TransformMap
)

func init() {
	// IKE
	Aes128Sha256Modp3072 = protocol.IkeTransform(
		protocol.ENCR_AES_CBC,
		128,
		protocol.AUTH_HMAC_SHA2_256_128,
		protocol.PRF_HMAC_SHA2_256,
		protocol.MODP_3072)

	Aes128Sha256Ecp256 = protocol.IkeTransform(
		protocol.ENCR_AES_CBC,
		128,
		protocol.AUTH_HMAC_SHA2_256_128,
		protocol.PRF_HMAC_SHA2_256,
		protocol.ECP_384)

	//ESP
	Aes128Sha256 = protocol.EspTransform(
		protocol.ENCR_AES_CBC,
		128,
		protocol.AUTH_HMAC_SHA2_256_128,
		protocol.ESN_NONE)

	IkeSuites["aes128-sha256-modp3072"] = Aes128Sha256Modp3072
	IkeSuites["aes128-sha256-ecp256"] = Aes128Sha256Ecp256
	EspSuites["aes128-sha256"] = Aes128Sha256
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// func cipherCamellia(key, iv []byte, isRead bool) interface{} {
// 	block, _ := camellia.New(key)
// 	if isRead {
// 		return cipher.NewCBCDecrypter(block, iv)
// 	}
// 	return cipher.NewCBCEncrypter(block, iv)
// }

// TODO - this needs a proper do nothing implementation
func cipherNull([]byte, []byte, bool) interface{} { return nil }

// TODO - check if the parameters are valid
func cipherTransform(cipherId uint16, keyLen int, cipher *simpleCipher) bool {
	blockSize, cipherFunc, ok := _cipherTransform(cipherId)
	if !ok {
		return false
	}
	cipher.keyLen = keyLen
	cipher.blockLen = blockSize
	cipher.ivLen = blockSize
	cipher.cipherFunc = cipherFunc
	cipher.EncrTransformId = protocol.EncrTransformId(cipherId)
	return true
}

func _cipherTransform(cipherId uint16) (int, cipherFunc, bool) {
	switch protocol.EncrTransformId(cipherId) {
	// case protocol.ENCR_CAMELLIA_CBC:
	// return camellia.BlockSize, cipherCamellia, true
	case protocol.ENCR_AES_CBC:
		return aes.BlockSize, cipherAES, true
	case protocol.ENCR_NULL:
		return 0, cipherNull, true
	default:
		return 0, nil, false
	}
}
