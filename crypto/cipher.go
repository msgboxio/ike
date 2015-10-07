package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"msgbox.io/ike/protocol"
	"msgbox.io/log"

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

// decryption & encryption routines

func decrypt(b, key []byte, ivLen int, cipherFn cipherFunc) (dec []byte, err error) {
	iv := b[0:ivLen]
	ciphertext := b[ivLen:]
	// block ciphers only yet
	mode := cipherFn(key, iv, true)
	if mode == nil {
		// null transform
		return b, nil
	}
	block := mode.(cipher.BlockMode)
	// CBC mode always works in whole blocks.
	if len(ciphertext)%block.BlockSize() != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		return
	}
	clear := make([]byte, len(ciphertext))
	block.CryptBlocks(clear, ciphertext)
	padlen := clear[len(clear)-1] + 1 // padlen byte itself
	if int(padlen) > block.BlockSize() {
		err = errors.New("pad length is larger than block size")
		return
	}
	dec = clear[:len(clear)-int(padlen)]
	if log.V(4) {
		log.Infof("Pad %d: Clear:\n%sCyp:\n%sIV:\n%s", padlen, hex.Dump(clear), hex.Dump(ciphertext), hex.Dump(iv))
	}
	return
}

func encrypt(clear, key []byte, ivLen int, cipherFn cipherFunc) (b []byte, err error) {
	iv, err := rand.Prime(rand.Reader, ivLen*8) // bits
	if err != nil {
		return
	}
	mode := cipherFn(key, iv.Bytes(), false)
	if mode == nil {
		// null transform
		return clear, nil
	}
	block := mode.(cipher.BlockMode)
	// CBC mode always works in whole blocks.
	// (b - (length % b)) % b
	// pl := (block.BlockSize() - (len(clear) % block.BlockSize())) % block.BlockSize()
	pl := block.BlockSize() - len(clear)%block.BlockSize()
	if pl != 0 {
		pad := make([]byte, pl)
		pad[pl-1] = byte(pl - 1)
		clear = append(clear, pad...)
	}
	cyp := make([]byte, len(clear))
	block.CryptBlocks(cyp, clear)
	b = append(iv.Bytes(), cyp...)
	if log.V(4) {
		log.Infof("Pad %d: Clear:\n%sCyp:\n%sIV:\n%s", pl, hex.Dump(clear), hex.Dump(cyp), hex.Dump(iv.Bytes()))
	}
	return

}
