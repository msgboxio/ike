package ike

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"msgbox.io/log"

	"github.com/dgryski/go-camellia"
)

// ike-seperation.pdf

// 2.1.2 IKE_SA_INIT
// tkm creates KEi, Ni

// get SKEYSEED
// derive SK_e (encryption) and SK_a (authentication)

// 2.1.3 IKE_AUTH
// tkm creates SK, AUTH

// 2.1.4 CREATE_CHILD_SA
// tkm creates SK, Ni, [KEi]

func NewTkmResponder(secret []byte, dhTransform DhTransformId, theirPublic, no *big.Int) (tkm *Tkm, err error) {
	tkm = &Tkm{
		isInitiator: false,
		Ni:          no,
		secret:      prf(secret, []byte("Key Pad for IKEv2"), HASH),
	}
	// at least 128 bits & at least half the key size of the negotiated prf
	if err := tkm.NcCreate(no.BitLen()); err != nil {
		return nil, err
	}
	if _, err := tkm.DhCreate(dhTransform); err != nil {
		return nil, err
	}
	if err := tkm.DhGenerateKey(theirPublic); err != nil {
		return nil, err
	}
	return tkm, nil
}

type Tkm struct {
	isInitiator bool

	secret []byte

	Nr, Ni *big.Int

	DhGroup             *dhGroup
	DhPrivate, DhPublic *big.Int
	DhShared            *big.Int

	SKEYSEED, KEYMAT                        []byte
	skD, skAi, skAr, skEi, skEr, skPi, skPr []byte

	IpsecKEYMAT                []byte
	espEi, espAi, espEr, espAr []byte
}

var (
	AUTH_MAC_SIZE = 32
	MACLEN        = 16
	HASH          = sha256.New

	IV_LEN_CAMELLIA = 16
)

// 4.1.2 creation of ike sa

// The client gets the Nr
func (t *Tkm) NcCreate(bits int) (err error) {
	no, err := rand.Prime(rand.Reader, bits)
	if t.isInitiator {
		t.Ni = no
	} else {
		t.Nr = no
	}
	return
}

// the client get the dh public value
func (t *Tkm) DhCreate(dhTransform DhTransformId) (n *big.Int, err error) {
	t.DhGroup, _ = kexAlgoMap[dhTransform]
	if t.DhGroup == nil {
		return nil, fmt.Errorf("Missing dh transfom %s", dhTransform)
	}
	t.DhPrivate, err = t.DhGroup.private(rand.Reader)
	if err != nil {
		return nil, err
	}
	t.DhPublic = t.DhGroup.public(t.DhPrivate)
	return t.DhPublic, nil
}

// upon receipt of peers resp, a dh shared secret can be calculated
// client creates & stores the dh key
func (t *Tkm) DhGenerateKey(theirPublic *big.Int) (err error) {
	t.DhShared, err = t.DhGroup.diffieHellman(theirPublic, t.DhPrivate)
	return
}

func prf(key, data []byte, h func() hash.Hash) []byte {
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func prfplus(key, data []byte, bits int, h func() hash.Hash) []byte {
	var ret, prev []byte
	var round int = 1
	for len(ret) < bits {
		prev = prf(key, append(append(prev, data...), byte(round)), h)
		ret = append(ret, prev...)
		round += 1
	}
	return ret[:bits]
}

// create ike sa
func (t *Tkm) IsaCreate(spiI, spiR []byte) {
	// SKEYSEED = prf(Ni | Nr, g^ir)
	t.SKEYSEED = prf(append(t.Ni.Bytes(), t.Nr.Bytes()...), t.DhShared.Bytes(), HASH)
	// keymat =  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	t.KEYMAT = prfplus(t.SKEYSEED,
		append(append(t.Ni.Bytes(), t.Nr.Bytes()...), append(spiI, spiR...)...),
		32*7, HASH)
	t.skD, t.skAi, t.skAr, t.skEi, t.skEr, t.skPi, t.skPr = t.KEYMAT[0:32], t.KEYMAT[32:32*2], t.KEYMAT[32*2:32*3], t.KEYMAT[32*3:32*4], t.KEYMAT[32*4:32*5], t.KEYMAT[32*5:32*6], t.KEYMAT[32*6:32*7]

	// fmt.Printf("\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
	// 	hex.Dump(t.skD),
	// 	hex.Dump(t.skAi),
	// 	hex.Dump(t.skAr),
	// 	hex.Dump(t.skEi),
	// 	hex.Dump(t.skEr),
	// 	hex.Dump(t.skPi),
	// 	hex.Dump(t.skPr))
}

// checkMAC returns true if messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(HASH, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)[:MACLEN]
	return hmac.Equal(messageMAC, expectedMAC)
}

// verify message appended with mac
func (t *Tkm) VerifyMac(b []byte) (err error) {
	l := len(b)
	mac := b[l-MACLEN:]
	msg := b[:l-MACLEN]
	key := t.skAi
	if t.isInitiator {
		key = t.skAr
	}
	if !checkMAC(msg, mac, key) {
		return errors.New("HMAC verify failed: ")
	}
	return
}

func (t *Tkm) Decrypt(b []byte) (dec []byte, err error) {
	iv := b[0:IV_LEN_CAMELLIA]
	ciphertext := b[IV_LEN_CAMELLIA:]
	key := t.skEi
	if t.isInitiator {
		key = t.skEr
	}
	block, err := camellia.New(key)
	if err != nil {
		return
	}
	// CBC mode always works in whole blocks.
	if len(ciphertext)%block.BlockSize() != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		return
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	padlen := ciphertext[len(ciphertext)-1] + 1 // padlen byte itself
	dec = ciphertext[:len(ciphertext)-int(padlen)]
	return
}

func (tkm *Tkm) VerifyDecrypt(ike []byte) (nextPayload PayloadType, dec []byte, err error) {
	b := ike[IKE_HEADER_LEN:]
	pHeader := &PayloadHeader{}
	if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
		return
	}
	if r := len(b) - int(pHeader.PayloadLength); r != 0 {
		log.Errorf("extra %d\n", r)
	}
	nextPayload = pHeader.NextPayload
	if err = tkm.VerifyMac(ike); err != nil {
		return
	}
	enc := b[PAYLOAD_HEADER_LENGTH : len(b)-MACLEN]
	// fmt.Printf("enc: \n%s", hex.Dump(enc))
	dec, err = tkm.Decrypt(enc)
	// fmt.Printf("dec: \n%s", hex.Dump(dec))
	return
}

func (*Tkm) HashLength() int {
	return MACLEN
}

func (tkm *Tkm) Mac(b []byte) (ret []byte) {
	key := tkm.skAr
	if tkm.isInitiator {
		key = tkm.skAi
	}
	mac := hmac.New(HASH, key)
	mac.Write(b)
	ret = mac.Sum(nil)[:MACLEN]
	return
}
func (tkm *Tkm) Encrypt(clear []byte) (b []byte, err error) {
	iv, err := rand.Prime(rand.Reader, IV_LEN_CAMELLIA*8)
	if err != nil {
		return
	}
	key := tkm.skEr
	if tkm.isInitiator {
		key = tkm.skEi
	}
	block, err := camellia.New(key)
	if err != nil {
		return
	}
	mode := cipher.NewCBCEncrypter(block, iv.Bytes())
	// CBC mode always works in whole blocks.
	if padlen := block.BlockSize() - len(clear)%block.BlockSize(); padlen != 0 {
		pad := make([]byte, padlen)
		pad[padlen-1] = byte(padlen - 1)
		clear = append(clear, pad...)
	}
	// fmt.Printf("dec1: \n%s", hex.Dump(clear))
	mode.CryptBlocks(clear, clear)
	// fmt.Printf("enc1: \n%s", hex.Dump(clear))
	b = append(iv.Bytes(), clear...)
	return
}

// signed
//  intiator:  signed1 | prf(sk_pi | IDi )
//  responder: signed1 | prf(sk_pr | IDr )
// AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), signed)
func (tkm *Tkm) Auth(signed1, id []byte, flag IkeFlags) []byte {
	key := tkm.skPr
	if flag.IsInitiator() {
		key = tkm.skPi
	}
	return prf(tkm.secret, append(signed1, prf(key, id, HASH)...), HASH)[:AUTH_MAC_SIZE]
}

func (t *Tkm) IpsecSaCreate(spiI, spiR []byte) {
	// KEYMAT = prf+(SK_d, Ni | Nr)
	t.IpsecKEYMAT = prfplus(t.skD, append(t.Ni.Bytes(), t.Nr.Bytes()...),
		32*4, HASH)
	t.espEi, t.espAi, t.espEr, t.espAr = t.KEYMAT[0:32], t.KEYMAT[32:32*2], t.KEYMAT[32*2:32*3], t.KEYMAT[32*3:32*4]
}

// request signed data from tkm
func isa_sign(isa_id, lc_id, init_message []byte) (AUTH_loc []byte) { return }

// cert validation
// start vaildating cert chain
func cc_set_user_certficate(cc_id, ri_id, au_tha_id, CERT []byte) {}

// add remianing certs in chain
func cc_add_certificate(cc_id, autha_id, CERT []byte) {}

// validate
func cc_check_ca(cc_id, ca_id []byte) {}

// after cert validtaion, authenticate peer
func isa_auth(isa_id, cc_id, init_message, AUTH_rem []byte) {}

// create first child sa
func esa_create_first(esa_id, isa_id, sp_id, ea_id, esp_spi_loc, esp_spi_rem []byte) {}
