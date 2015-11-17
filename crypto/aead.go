package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"msgbox.io/ike/protocol"
)

/*

AES-GCM :
cipher - AES block cipher in Counter Mode (AES-CTR).
MAC-  it uses a universal hash called GHASH, encrypted with AES-CTR.

AES-CCM :

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

K - key; 128, 192 or 256 bit; fn(ks_ex)
N - 12B (11 for CCM), Salt(not in payload) + IV
IV - 8B
ICV(T, auth tag) - integ check value; 16 B, MAY support 8, 12 B; fn(A,C)

len(C) == len(P) + len(T)
C,T <= fn(K, N, P, A)

ICV 12 is not recommended
K 192 bits is not recommended

length of SK_ai and SK_ar is 0
SK_ei and SK_er include salt bytes
if keyLen is 128, then 20 bytes (16B + 4B salt)

*/

type aeadFunc func(key []byte) (cipher.AEAD, error)

func aeadTransform(cipherId uint16, keyLen int, cipher *aeadCipher) (*aeadCipher, bool) {
	blockLen, saltLen, ivLen, aeadFunc := _aeadTransform(cipherId)
	if aeadFunc == nil {
		return nil, false
	}
	if cipher == nil {
		cipher = &aeadCipher{}
	}
	cipher.blockLen = blockLen
	cipher.keyLen = keyLen
	cipher.saltLen = saltLen
	cipher.ivLen = ivLen
	cipher.saltLen = saltLen
	return cipher, true
}

func _aeadTransform(cipherId uint16) (blockLen, saltLen, ivLen int, aeadFunc aeadFunc) {
	switch protocol.EncrTransformId(cipherId) {
	case protocol.ENCR_AES_GCM_8:
	case protocol.ENCR_AES_GCM_16:
		return 16, 4, 8, func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	default:
	}
	return 0, 0, 0, nil
}

type aeadCipher struct {
	aeadFunc
	blockLen, keyLen, saltLen, ivLen int
}

func (cs *aeadCipher) Overhead(clear []byte) int {
	return cs.blockLen - len(clear)%cs.blockLen + cs.ivLen
}

const ADLEN = protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH + 8

func (cs *aeadCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	key := skE[:cs.keyLen-cs.saltLen]
	salt := skE[cs.keyLen:]
	aead, err2 := cs.aeadFunc(key)
	if err2 != nil {
		err = err2
		return
	}
	ad := ike[:ADLEN]
	ct := ike[ADLEN+cs.ivLen:]
	iv := ike[ADLEN : ADLEN+cs.ivLen]
	nonce := append(salt, iv...) // 12B; 4B salt + 8B iv
	clear, err2 := aead.Open([]byte{}, nonce, ct, ad)
	if err2 != nil {
		err = err2
		return
	}
	// remove pad
	padlen := clear[len(clear)-1] + 1 // padlen byte itself
	if int(padlen) > cs.blockLen {
		err = errors.New("pad length is larger than block size")
		return
	}
	dec = clear[:len(clear)-int(padlen)]
	return
}

func (cs *aeadCipher) EncryptMac(headers, payload, skA, skE []byte) (encr []byte, err error) {
	key := skE[:cs.keyLen-cs.saltLen]
	salt := skE[cs.keyLen:]
	aead, err := cs.aeadFunc(key)
	if err != nil {
		return
	}
	iv, err := rand.Prime(rand.Reader, cs.ivLen*8) // bits
	if err != nil {
		return
	}
	nonce := append(salt, iv.Bytes()...)
	// pad
	padlen := cs.blockLen - len(payload)%cs.blockLen
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1) // write length
		payload = append(payload, pad...)
	}
	encr = aead.Seal([]byte{}, nonce, payload, headers)
	return
}
