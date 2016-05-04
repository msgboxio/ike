package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
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

2 outputs:
	plaintext
	auth tag (icv)

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
Salt - GCM (4B), CCM (3B)
N - 12B (11 for CCM), Salt(not in payload) + IV
IV - 8B (GCM & CCM)
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
	default:
	}
	return
}

type aeadCipher struct {
	aeadFunc
	blockLen, keyLen, saltLen, ivLen, icvLen int
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
	if log.V(4) {
		log.Infof("aead Verify&Decrypt:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sCT:\n%sICV:\n%s",
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
	if log.V(4) {
		log.Infof("Padlen:%d\nClear:\n%s",
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
	nonce := append(append([]byte{}, salt...), ivBytes...)
	// pad
	padlen := cs.blockLen - len(payload)%cs.blockLen
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1) // write length
		payload = append(payload, pad...)
	}
	encr = aead.Seal([]byte{}, nonce, payload, headers)
	if log.V(4) {
		log.Infof("aead encrypt&mac:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sPadlen:%d\nICV\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(ivBytes), hex.Dump(headers), padlen, hex.Dump(encr[len(payload):]))
	}
	encr = append(append(headers, ivBytes...), encr...)
	return
}
