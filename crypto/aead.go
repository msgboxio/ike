package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"msgbox.io/ike/protocol"
	"msgbox.io/log"
)

/*

AES-CCM :

AES-GCM :
cipher - AES block cipher in Counter Mode (AES-CTR).
MAC-  it uses a universal hash called GHASH, encrypted with AES-CTR.

4 inputs:
	secret key
	IV (called nonce in ESP context, to differentiate from IKE IV)
	plaintext
	input for additional authenticated data (AAD)

2 inputs:
	plaintext
	auth tag

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

func aeadTransform(cipherId uint16, keyLen int, cipher *aeadCipher) (*aeadCipher, int, bool) {
	blockLen, saltLen, ivLen, aeadFunc := _aeadTransform(cipherId)
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
	return cipher, cipher.keyLen + cipher.saltLen, true
}

func _aeadTransform(cipherId uint16) (blockLen, saltLen, ivLen int, aeadFunc aeadFunc) {
	switch protocol.EncrTransformId(cipherId) {
	case protocol.AEAD_AES_GCM_8:
	case protocol.AEAD_AES_GCM_16:
		return 16, 4, 8, func(key []byte) (cipher.AEAD, error) {
			// TODO - make sure key length is same as configured
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

const ADLEN = protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH

func (cs *aeadCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	key := skE[:cs.keyLen]
	salt := skE[cs.keyLen : cs.keyLen+cs.saltLen]
	aead, err2 := cs.aeadFunc(key)
	if err2 != nil {
		err = err2
		return
	}
	ad := ike[:ADLEN]
	iv := ike[ADLEN : ADLEN+cs.ivLen]
	ct := ike[ADLEN+cs.ivLen:]
	nonce := append(salt, iv...) // 12B; 4B salt + 8B iv
	if log.V(4) {
		log.Infof("aead Verify&Decrypt: Key:\n%sSalt:\n%sNonce:\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(nonce))
	}
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
	if log.V(4) {
		log.Infof("aead Verify&Decrypt: Padlen:%d\nClear\n:%s",
			padlen, hex.Dump(clear))
	}
	return
}

func (cs *aeadCipher) EncryptMac(headers, payload, skA, skE []byte) (encr []byte, err error) {
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
	nonce := append(salt, ivBytes...)
	// pad
	padlen := cs.blockLen - len(payload)%cs.blockLen
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1) // write length
		payload = append(payload, pad...)
	}
	encr = append(append(headers, ivBytes...), aead.Seal([]byte{}, nonce, payload, headers)...)
	if log.V(4) {
		log.Infof("aead encrypt&mac: Key:\n%sSalt:\n%sNonce:\n%sPadlen:%d",
			hex.Dump(key), hex.Dump(salt), hex.Dump(nonce), padlen)
	}
	return
}
