package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"

	"github.com/msgboxio/ike/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

/*

sk payload ->
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Next Payload  !C!  RESERVED   !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !                     Initialization Vector                     !
   !                              8B                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                        Ciphertext (C)                         ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

P (plaintext) ->
                           1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                 IKE Payloads to be Encrypted                  ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !               !             Padding (0-255 octets)            !
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   !                                               !  Pad Length   !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

A (additional data) ->
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                         IKEv2 Header                          ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                   Unencrypted IKE Payloads                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Next Payload  !C!  RESERVED   !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

length of SK_ai and SK_ar is 0
SK_ei and SK_er include salt bytes
if keyLen is 128, then 20 bytes (16B + 4B salt)

*/

type aeadFunc func(key []byte) (cipher.AEAD, error)

// TODO - check if the parameters are valid
func aeadTransform(cipherId uint16, keyLen int, cipher *aeadCipher) (*aeadCipher, int, bool) {
	blockLen, saltLen, ivLen, icvLen, aeadFunc := _aeadTransform(cipherId)
	if aeadFunc == nil {
		return nil, 0, false
	}
	if cipher == nil {
		cipher = &aeadCipher{aeadFunc: aeadFunc}
	}
	cipher.blockLen = blockLen
	cipher.keyLen = keyLen
	cipher.saltLen = saltLen
	cipher.ivLen = ivLen
	cipher.saltLen = saltLen
	cipher.icvLen = icvLen
	cipher.EncrTransformId = protocol.EncrTransformId(cipherId)
	// return length of key that needs to be derived
	return cipher, cipher.keyLen + cipher.saltLen, true
}

func _aeadTransform(cipherId uint16) (blockLen, saltLen, ivLen, icvLen int, aeadFunc aeadFunc) {
	switch protocol.EncrTransformId(cipherId) {
	case protocol.AEAD_AES_GCM_8:
	case protocol.AEAD_AES_GCM_16:
		return 16, 4, 8, 16, func(key []byte) (cipher.AEAD, error) {
			// TODO - make sure key length is same as configured
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case protocol.AEAD_CHACHA20_POLY1305:
		return 16, 4, 8, 16, func(key []byte) (cipher.AEAD, error) {
			// TODO - make sure key length is same as configured
			return chacha20poly1305.New(key)
		}
	default:
	}
	return
}

type aeadCipher struct {
	aeadFunc
	blockLen, keyLen, saltLen, ivLen, icvLen int

	protocol.EncrTransformId
}

func (cs *aeadCipher) String() string {
	return cs.EncrTransformId.String()
}

func (cs *aeadCipher) Overhead(clear []byte) int {
	// padding + iv + icv
	padlen := cs.blockLen - len(clear)%cs.blockLen
	return padlen + cs.ivLen + cs.icvLen
}

const ADLEN = protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH

func (cs *aeadCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	// Encryption key has salt appended to it
	key := skE[:cs.keyLen]
	salt := skE[cs.keyLen : cs.keyLen+cs.saltLen]
	aead, err := cs.aeadFunc(key)
	if err != nil {
		return
	}
	ad := ike[:ADLEN]
	iv := ike[ADLEN : ADLEN+cs.ivLen]
	ct := ike[ADLEN+cs.ivLen : len(ike)-cs.icvLen]
	icv := ike[len(ike)-cs.icvLen:]
	nonce := append(append([]byte{}, salt...), iv...) // 12B; 4B salt + 8B iv
	if debugCrypto {
		log.Printf("aead Verify&Decrypt:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sCT:\n%sICV:\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(iv), hex.Dump(ad), hex.Dump(ct), hex.Dump(icv))
	}
	clear, err := aead.Open([]byte{}, nonce, append(ct, icv...), ad)
	if err != nil {
		return
	}
	// remove pad
	padlen := clear[len(clear)-1] + 1 // padlen byte itself
	if int(padlen) > cs.blockLen {
		err = errors.New("pad length is larger than block size")
		return
	}
	dec = clear[:len(clear)-int(padlen)]
	if debugCrypto {
		log.Printf("Padlen:%d\nClear:\n%s", padlen, hex.Dump(clear))
	}
	return
}

func (cs *aeadCipher) EncryptMac(ike, skA, skE []byte) (encr []byte, err error) {
	hlen := protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH
	headers := ike[:hlen] // additional data
	payload := ike[hlen:]
	key := skE[:cs.keyLen]
	salt := skE[cs.keyLen : cs.keyLen+cs.saltLen]
	aead, err := cs.aeadFunc(key)
	if err != nil {
		return
	}
	iv, err := rand.Prime(rand.Reader, cs.ivLen*8) // bits
	if err != nil {
		return
	}
	ivBytes := iv.Bytes()
	nonce := append(append([]byte{}, salt...), ivBytes...)
	// pad
	padlen := cs.blockLen - len(payload)%cs.blockLen
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1) // write length
		payload = append(append([]byte{}, payload...), pad...)
	}
	encr = aead.Seal([]byte{}, nonce, payload, headers)
	if debugCrypto {
		log.Printf("aead encrypt&mac:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sPadlen:%d\nICV\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(ivBytes), hex.Dump(headers), padlen, hex.Dump(encr[len(payload):]))
	}
	encr = append(append(append([]byte{}, headers...), ivBytes...), encr...)
	return
}
