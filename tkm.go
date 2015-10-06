package ike

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"msgbox.io/ike/crypto"
	"msgbox.io/ike/protocol"
	"msgbox.io/log"
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

type Tkm struct {
	suite       *crypto.CipherSuite
	isInitiator bool

	ids Identities

	Nr, Ni *big.Int

	dhPrivate, DhPublic *big.Int
	DhShared            *big.Int

	// for debug
	SKEYSEED, KEYMAT []byte

	skD        []byte // further keying material for child sa
	skPi, skPr []byte // used when generating an AUTH
	skAi, skAr []byte // integrity protection keys
	skEi, skEr []byte // encryption keys
}

func NewTkmInitiator(suite *crypto.CipherSuite, ids Identities) (tkm *Tkm, err error) {
	tkm = &Tkm{
		suite:       suite,
		isInitiator: true,
		ids:         ids,
	}
	// standard says nonce shwould be at least half of size of negotiated prf
	if ni, err := tkm.ncCreate(suite.PrfLen * 8); err != nil {
		return nil, err
	} else {
		tkm.Ni = ni
	}
	// for sending public key
	if _, err := tkm.dhCreate(); err != nil {
		return nil, err
	}
	return tkm, nil
}

func NewTkmResponder(suite *crypto.CipherSuite, theirPublic, no *big.Int, ids Identities) (tkm *Tkm, err error) {
	tkm = &Tkm{
		suite: suite,
		Ni:    no,
		ids:   ids,
	}
	// at least 128 bits & at least half the key size of the negotiated prf
	if nr, err := tkm.ncCreate(no.BitLen()); err != nil {
		return nil, err
	} else {
		tkm.Nr = nr
	}
	if _, err := tkm.dhCreate(); err != nil {
		return nil, err
	}
	if err := tkm.DhGenerateKey(theirPublic); err != nil {
		return nil, err
	}
	return tkm, nil
}

// 4.1.2 creation of ike sa

func (t *Tkm) ncCreate(bits int) (no *big.Int, err error) {
	return rand.Prime(rand.Reader, bits)
}

// the client get the dh public value
func (t *Tkm) dhCreate() (n *big.Int, err error) {
	t.dhPrivate, err = t.suite.DhGroup.Private(rand.Reader)
	if err != nil {
		return nil, err
	}
	t.DhPublic = t.suite.DhGroup.Public(t.dhPrivate)
	return t.DhPublic, nil
}

// upon receipt of peers resp, a dh shared secret can be calculated
// client creates & stores the dh key
func (t *Tkm) DhGenerateKey(theirPublic *big.Int) (err error) {
	t.DhShared, err = t.suite.DhGroup.DiffieHellman(theirPublic, t.dhPrivate)
	return
}

func (t *Tkm) prfplus(key, data []byte, bits int) []byte {
	var ret, prev []byte
	var round int = 1
	for len(ret) < bits {
		prev = t.suite.Prf(key, append(append(prev, data...), byte(round)))
		ret = append(ret, prev...)
		round += 1
	}
	return ret[:bits]
}

func (t *Tkm) SkeySeedInitial() []byte {
	// SKEYSEED = prf(Ni | Nr, g^ir)
	return t.suite.Prf(append(t.Ni.Bytes(), t.Nr.Bytes()...), t.DhShared.Bytes())
}

func (t *Tkm) SkeySeedRekey(old_SK_D []byte) []byte {
	// SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
	return t.suite.Prf(old_SK_D, append(t.DhShared.Bytes(), append(t.Ni.Bytes(), t.Nr.Bytes()...)...))
}

// create ike sa
func (t *Tkm) IsaCreate(spiI, spiR protocol.Spi, old_SK_D []byte) {
	// fmt.Printf("key inputs: \nni:\n%snr:\n%sshared:\n%sspii:\n%sspir:\n%s",
	// 	hex.Dump(t.Ni.Bytes()), hex.Dump(t.Nr.Bytes()), hex.Dump(t.DhShared.Bytes()),
	// 	hex.Dump(spiI), hex.Dump(spiR))
	SKEYSEED := []byte{}
	if len(old_SK_D) == 0 {
		SKEYSEED = t.SkeySeedInitial()
	} else {
		SKEYSEED = t.SkeySeedRekey(old_SK_D)
	}
	kmLen := 3*t.suite.PrfLen + 2*t.suite.KeyLen + 2*t.suite.MacKeyLen
	// keymat =  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	KEYMAT := t.prfplus(SKEYSEED,
		append(append(t.Ni.Bytes(), t.Nr.Bytes()...), append(spiI, spiR...)...),
		kmLen)

	// SK_d, SK_pi, and SK_pr MUST be prfLength
	offset := t.suite.PrfLen
	t.skD = KEYMAT[0:offset]
	t.skAi = KEYMAT[offset : offset+t.suite.MacKeyLen]
	offset += t.suite.MacKeyLen
	t.skAr = KEYMAT[offset : offset+t.suite.MacKeyLen]
	offset += t.suite.MacKeyLen
	t.skEi = KEYMAT[offset : offset+t.suite.KeyLen]
	offset += t.suite.KeyLen
	t.skEr = KEYMAT[offset : offset+t.suite.KeyLen]
	offset += t.suite.KeyLen
	t.skPi = KEYMAT[offset : offset+t.suite.PrfLen]
	offset += t.suite.PrfLen
	t.skPr = KEYMAT[offset : offset+t.suite.PrfLen]

	// for test
	t.KEYMAT = KEYMAT
	t.SKEYSEED = SKEYSEED
	// fmt.Printf("keymat length %d\n", len(KEYMAT))
	// fmt.Printf("\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
	// 	hex.Dump(t.skD),
	// 	hex.Dump(t.skAi),
	// 	hex.Dump(t.skAr),
	// 	hex.Dump(t.skEi),
	// 	hex.Dump(t.skEr),
	// 	hex.Dump(t.skPi),
	// 	hex.Dump(t.skPr))
}

// verify message appended with mac
func (t *Tkm) verifyMac(b []byte) (err error) {
	key := t.skAi
	if t.isInitiator {
		key = t.skAr
	}
	l := len(b)
	msg := b[:l-t.suite.MacLen]
	msgMAC := b[l-t.suite.MacLen:]
	expectedMAC := t.suite.Mac(key, msg)[:t.suite.MacLen]
	if !hmac.Equal(msgMAC, expectedMAC) {
		return fmt.Errorf("HMAC verify failed: \n%s\nvs\n%s",
			hex.Dump(msgMAC), hex.Dump(expectedMAC))
	}
	return
}

func (t *Tkm) decrypt(b []byte) (dec []byte, err error) {
	key := t.skEi
	if t.isInitiator {
		key = t.skEr
	}
	iv := b[0:t.suite.IvLen]
	ciphertext := b[t.suite.IvLen:]
	// block ciphers only yet
	mode := t.suite.Cipher(key, iv, true)
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

// MAC-then-decrypt
func (t *Tkm) VerifyDecrypt(ike []byte) (dec []byte, err error) {
	b := ike[protocol.IKE_HEADER_LEN:]
	if err = t.verifyMac(ike); err != nil {
		return
	}
	dec, err = t.decrypt(b[protocol.PAYLOAD_HEADER_LENGTH : len(b)-t.suite.MacLen])
	return
}

func (t *Tkm) encrypt(clear []byte) (b []byte, err error) {
	key := t.skEr
	if t.isInitiator {
		key = t.skEi
	}
	iv, err := rand.Prime(rand.Reader, t.suite.IvLen*8) // bits
	if err != nil {
		return
	}
	mode := t.suite.Cipher(key, iv.Bytes(), false)
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

func (t *Tkm) mac(b []byte) []byte {
	macKey := t.skAr
	if t.isInitiator {
		macKey = t.skAi
	}
	return t.suite.Mac(macKey, b)
}

// encrypt-then-MAC
func (t *Tkm) EncryptMac(s *Message) (b []byte, err error) {
	// encrypt the remaining payloads
	encr, err := t.encrypt(protocol.EncodePayloads(s.Payloads))
	if err != nil {
		return
	}
	firstPayload := protocol.PayloadTypeNone // no payloads are one possibility
	if len(s.Payloads.Array) > 0 {
		firstPayload = s.Payloads.Array[0].Type()
	}
	// append to new secure payload
	h := protocol.PayloadHeader{
		NextPayload:   firstPayload,
		PayloadLength: uint16(len(encr) + t.suite.MacLen),
	}
	b = append(h.Encode(), encr...)
	// prepare proper ike header
	s.IkeHeader.MsgLength = uint32(len(b) + protocol.IKE_HEADER_LEN + t.suite.MacLen)
	// encode and append ike header
	b = append(s.IkeHeader.Encode(), b...)
	// finally attach mac
	b = append(b, t.mac(b)...)
	return
}

func (t *Tkm) AuthId(idType protocol.IdType) []byte {
	return t.ids.ForAuthentication(idType)
}

// signed
//  intiator:  signed1 | prf(sk_pi | IDi )
//  responder: signed1 | prf(sk_pr | IDr )
// AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), signed)
func (t *Tkm) Auth(signed1 []byte, id *protocol.IdPayload, method protocol.AuthMethod, flag protocol.IkeFlags) []byte {
	key := t.skPr
	if flag.IsInitiator() {
		key = t.skPi
	}
	signed := append(signed1, t.suite.Prf(key, id.Encode())...)
	secret := t.ids.AuthData(id.Data, method)
	secret = t.suite.Prf(secret, []byte("Key Pad for IKEv2"))
	return t.suite.Prf(secret, signed)[:t.suite.PrfLen]
}

func (t *Tkm) IpsecSaCreate(spiI, spiR protocol.Spi) (espEi, espAi, espEr, espAr []byte) {
	kmLen := 2*t.suite.KeyLen + 2*t.suite.MacKeyLen
	// KEYMAT = prf+(SK_d, Ni | Nr)
	KEYMAT := t.prfplus(t.skD, append(t.Ni.Bytes(), t.Nr.Bytes()...),
		kmLen)

	offset := t.suite.KeyLen
	espEi = KEYMAT[0:offset]
	espAi = KEYMAT[offset : offset+t.suite.MacKeyLen]
	offset += t.suite.MacKeyLen
	espEr = KEYMAT[offset : offset+t.suite.KeyLen]
	offset += t.suite.KeyLen
	espAr = KEYMAT[offset : offset+t.suite.MacKeyLen]
	// fmt.Printf("ESP keys : \n%s\n%s\n%s\n%s\n",
	// 	hex.Dump(espEi),
	// 	hex.Dump(espAi),
	// 	hex.Dump(espEr),
	// 	hex.Dump(espAr))
	return
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
