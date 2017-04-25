package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"

	"github.com/msgboxio/ike/protocol"
)

/*
rfc5282
Using Authenticated Encryption Algorithms with the Encrypted Payload
        of the Internet Key Exchange version 2 (IKEv2) Protocol

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
if keyLen is 128, then 20 bits (16B + 4B salt)
ICV is atag
*/

type aeadFunc func(key []byte) (cipher.AEAD, error)

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

const aadLen = protocol.IKE_HEADER_LEN + protocol.PAYLOAD_HEADER_LENGTH

func (cs *aeadCipher) VerifyDecrypt(ike, skA, skE []byte) (dec []byte, err error) {
	// Encryption key has salt appended to it
	key := skE[:cs.keyLen]
	salt := skE[cs.keyLen : cs.keyLen+cs.saltLen]
	aead, err := cs.aeadFunc(key)
	if err != nil {
		return
	}
	aad := ike[:aadLen]
	iv := ike[aadLen : aadLen+cs.ivLen]
	ct := ike[aadLen+cs.ivLen:]
	nonce := append(append([]byte{}, salt...), iv...) // 12B; 4B salt + 8B iv
	if DebugCrypto {
		log.Printf("aead Verify&Decrypt:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sCT:\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(iv), hex.Dump(aad), hex.Dump(ct))
	}
	clear, err := aead.Open([]byte{}, nonce, ct, aad)
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
	if DebugCrypto {
		log.Printf("Padlen:%d Clear:\n%s", padlen, hex.Dump(clear))
	}
	return
}

func (cs *aeadCipher) EncryptMac(ike, skA, skE []byte) (encr []byte, err error) {
	key := skE[:cs.keyLen]
	salt := skE[cs.keyLen : cs.keyLen+cs.saltLen]
	aead, err := cs.aeadFunc(key)
	if err != nil {
		return
	}
	aad := ike[:aadLen]                            // additional data
	iv, err := rand.Prime(rand.Reader, cs.ivLen*8) // bits
	if err != nil {
		return
	}
	ivBytes := iv.Bytes()
	payload := ike[aadLen:]
	nonce := append(append([]byte{}, salt...), ivBytes...)
	// pad
	padlen := cs.blockLen - len(payload)%cs.blockLen
	if padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1) // write length
		payload = append(append([]byte{}, payload...), pad...)
	}
	encr = aead.Seal([]byte{}, nonce, payload, aad)
	if DebugCrypto {
		log.Printf("aead encrypt&mac:\nKey:\n%sSalt:\n%sIV:\n%sAd:\n%sPadlen:%d\nencr\n%s",
			hex.Dump(key), hex.Dump(salt), hex.Dump(ivBytes), hex.Dump(aad), padlen, hex.Dump(encr))
	}
	encr = append(append(append([]byte{}, aad...), ivBytes...), encr...)
	return
}
