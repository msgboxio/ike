package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"

	"github.com/msgboxio/ike/protocol"
)

// Must returm an interface
// Interface can be either cipher.BlockMode or cipher.Stream
type cipherFunc func(key, iv []byte, isRead bool) interface{}

type simpleCipher struct {
	macTruncLen, macLen int
	macFunc

	keyLen, ivLen, blockLen int
	cipherFunc

	protocol.EncrTransformId
	protocol.AuthTransformId
}

func (cs *simpleCipher) String() string {
	return cs.EncrTransformId.String() + "+" + cs.AuthTransformId.String()
}

func (cs *simpleCipher) Overhead(clear []byte) int {
	return cs.blockLen - len(clear)%cs.blockLen + cs.macLen + cs.ivLen
}
func (cs *simpleCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	if DebugCrypto {
		log.Printf("simple verify&decrypt:Clear:\n%sSkA:\n%sSkE\n%s",
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

func (cs *simpleCipher) EncryptMac(ike, skA, skE []byte) (b []byte, err error) {
	hlen := protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH
	headers := ike[:hlen]
	payload := ike[hlen:]
	// encrypt-then-MAC
	encr, err := encrypt(payload, skE, cs.ivLen, cs.cipherFunc)
	if err != nil {
		return
	}
	data := append(headers, encr...)
	mac := cs.macFunc(skA, data)
	b = append(data, mac...)
	if DebugCrypto {
		log.Printf("simple encrypt&mac:\nMac:\n%sSkA\n%sSkE\n%s",
			hex.Dump(mac), hex.Dump(skA), hex.Dump(skE))
	}
	return
}

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
	if DebugCrypto {
		log.Printf("Pad %d: Clear:\n%sCyp:\n%sIV:\n%s", padlen, hex.Dump(clear), hex.Dump(ciphertext), hex.Dump(iv))
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
	padlen := block.BlockSize() - len(clear)%block.BlockSize()
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1)
		clear = append(clear, pad...)
	}
	ciphertext := make([]byte, len(clear))
	block.CryptBlocks(ciphertext, clear)
	b = append(iv.Bytes(), ciphertext...)
	if DebugCrypto {
		log.Printf("Pad %d: Clear:\n%sIV:\n%sCyp:\n%s",
			padlen, hex.Dump(clear), hex.Dump(iv.Bytes()), hex.Dump(ciphertext))
	}
	return
}
