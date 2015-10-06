package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"msgbox.io/ike/protocol"

	"github.com/dgryski/go-camellia"
)

// Must returm an interface
// because we can return either cipher.BlockMode or cipher.Stream
type cipherFunc func(key, iv []byte, isRead bool) interface{}

func cipherTransform(cipherId uint16) (ivLen int, ciperFunc cipherFunc, ok bool) {
	switch protocol.EncrTransformId(cipherId) {
	case protocol.ENCR_CAMELLIA_CBC:
		return camellia.BlockSize, cipherCamellia, true
	case protocol.ENCR_AES_CBC:
		return aes.BlockSize, cipherAES, true
	case protocol.ENCR_NULL:
		return 0, cipherNull, true
	default:
		return 0, nil, false
	}
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherCamellia(key, iv []byte, isRead bool) interface{} {
	block, _ := camellia.New(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherNull([]byte, []byte, bool) interface{} { return nil }
