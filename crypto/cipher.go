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
// Interface can be either cipher.BlockMode or cipher.Stream
type cipherFunc func(key, iv []byte, isRead bool) interface{}

func (cipherFunc) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func cipherTransform(cipherId uint16, keyLen int, cipher *simpleCipher) (*simpleCipher, bool) {
	blockSize, cipherFunc, ok := _cipherTransform(cipherId)
	if !ok {
		return nil, false
	}
	if cipher == nil {
		cipher = &simpleCipher{}
	}
	cipher.keyLen = keyLen
	cipher.blockLen = blockSize
	cipher.ivLen = blockSize
	cipher.cipherFunc = cipherFunc
	return cipher, true
}

func _cipherTransform(cipherId uint16) (int, cipherFunc, bool) {
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

// Cipher interface implementation

type simpleCipher struct {
	macKeyLen, macLen int
	macFunc

	keyLen, ivLen, blockLen int
	cipherFunc
}

func (cs *simpleCipher) Overhead(clear []byte) int {
	return cs.blockLen - len(clear)%cs.blockLen + cs.macLen + cs.ivLen
}
func (cs *simpleCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	if log.V(4) {
		log.Infof("simple verify&decrypt:Clear:\n%sSkA:\n%sSkE\n%s",
			hex.Dump(ike), hex.Dump(skA), hex.Dump(skE))
	}
	// MAC-then-decrypt
	if err = verifyMac(skA, ike, cs.macLen, cs.macFunc); err != nil {
		return
	}
	b := ike[protocol.IKE_HEADER_LEN:]
	dec, err = decrypt(b[protocol.PAYLOAD_HEADER_LENGTH:len(b)-cs.macLen], skE, cs.ivLen, cs.cipherFunc)
	return
}
func (cs *simpleCipher) EncryptMac(headers, payload, skA, skE []byte) (b []byte, err error) {
	// encrypt-then-MAC
	encr, err := encrypt(payload, skE, cs.ivLen, cs.cipherFunc)
	if err != nil {
		return
	}
	data := append(headers, encr...)
	mac := cs.macFunc(skA, data)
	b = append(data, mac...)
	if log.V(4) {
		log.Infof("simple encrypt&mac:\nMac:\n%sSkA\n%sSkE\n%s",
			hex.Dump(mac), hex.Dump(skA), hex.Dump(skE))
	}
	return
}

// cipherFunc Implementations

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

// TODO - this needs a proper do nothing implementation
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
	// TODO - block mode supported only
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
		log.Infof("Pad %d: Clear:\n%sIV:\n%sCyp:\n%s",
			pl, hex.Dump(clear), hex.Dump(iv.Bytes()), hex.Dump(cyp))
	}
	return
}
