package ike

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"math/big"
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
	suite       *cipherSuite
	isInitiator bool

	secret []byte
	authId []byte

	Nr, Ni *big.Int

	DhPrivate, DhPublic *big.Int
	DhShared            *big.Int

	SKEYSEED, KEYMAT []byte
	// size is preferred key lenght of prf
	skD        []byte // further keying material for child sa
	skPi, skPr []byte
	skAi, skAr []byte // integrity protection keys
	skEi, skEr []byte // encryption keys

	IpsecKEYMAT                []byte
	espEi, espAi, espEr, espAr []byte
}

func NewTkmInitiator(suite *cipherSuite) (tkm *Tkm, err error) {
	tkm = &Tkm{
		suite:       suite,
		isInitiator: true,
	}
	// standard says nonce shwould be at least half of size of negotiated prf
	if err := tkm.NcCreate(suite.prfLen * 8); err != nil {
		return nil, err
	}
	// for sending public key
	if _, err := tkm.DhCreate(); err != nil {
		return nil, err
	}
	return tkm, nil
}

func NewTkmResponder(suite *cipherSuite, theirPublic, no *big.Int) (tkm *Tkm, err error) {
	tkm = &Tkm{
		suite: suite,
		Ni:    no,
	}
	// at least 128 bits & at least half the key size of the negotiated prf
	if err := tkm.NcCreate(no.BitLen()); err != nil {
		return nil, err
	}
	if _, err := tkm.DhCreate(); err != nil {
		return nil, err
	}
	if err := tkm.DhGenerateKey(theirPublic); err != nil {
		return nil, err
	}
	return tkm, nil
}

func (t *Tkm) SetSecret(authId, secret []byte) {
	t.secret = t.suite.prf(secret, []byte("Key Pad for IKEv2"))
	t.authId = authId
}

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
func (t *Tkm) DhCreate() (n *big.Int, err error) {
	t.DhPrivate, err = t.suite.dhGroup.private(rand.Reader)
	if err != nil {
		return nil, err
	}
	t.DhPublic = t.suite.dhGroup.public(t.DhPrivate)
	return t.DhPublic, nil
}

// upon receipt of peers resp, a dh shared secret can be calculated
// client creates & stores the dh key
func (t *Tkm) DhGenerateKey(theirPublic *big.Int) (err error) {
	t.DhShared, err = t.suite.dhGroup.diffieHellman(theirPublic, t.DhPrivate)
	return
}

func (t *Tkm) prfplus(key, data []byte, bits int) []byte {
	var ret, prev []byte
	var round int = 1
	for len(ret) < bits {
		prev = t.suite.prf(key, append(append(prev, data...), byte(round)))
		ret = append(ret, prev...)
		round += 1
	}
	return ret[:bits]
}

// create ike sa
func (t *Tkm) IsaCreate(spiI, spiR []byte) {
	// SKEYSEED = prf(Ni | Nr, g^ir)
	SKEYSEED := t.suite.prf(append(t.Ni.Bytes(), t.Nr.Bytes()...), t.DhShared.Bytes())
	// keymat =  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	plen := t.suite.prfLen
	// TODO - supports 32B keys only
	KEYMAT := t.prfplus(SKEYSEED,
		append(append(t.Ni.Bytes(), t.Nr.Bytes()...), append(spiI, spiR...)...),
		plen*7)

	t.skD, t.skAi, t.skAr, t.skEi, t.skEr, t.skPi, t.skPr =
		KEYMAT[0:plen],
		KEYMAT[plen:plen*2],
		KEYMAT[plen*2:plen*3],
		KEYMAT[plen*3:plen*4],
		KEYMAT[plen*4:plen*5],
		KEYMAT[plen*5:plen*6],
		KEYMAT[plen*6:plen*7]

	// for test
	t.KEYMAT = KEYMAT
	t.SKEYSEED = SKEYSEED
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
func (t *Tkm) VerifyMac(b []byte) (err error) {
	key := t.skAi
	if t.isInitiator {
		key = t.skAr
	}
	l := len(b)
	msg := b[:l-t.suite.macLen]
	msgMAC := b[l-t.suite.macLen:]
	expectedMAC := t.suite.mac(key, msg)[:t.suite.macLen]
	if !hmac.Equal(msgMAC, expectedMAC) {
		return errors.New("HMAC verify failed: ")
	}
	return
}

func (t *Tkm) Decrypt(b, key []byte) (dec []byte, err error) {
	iv := b[0:t.suite.ivLen]
	ciphertext := b[t.suite.ivLen:]
	// block ciphers only yet
	mode := t.suite.cipher(key, iv, true).(cipher.BlockMode)
	// CBC mode always works in whole blocks.
	if len(ciphertext)%mode.BlockSize() != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		return
	}
	mode.CryptBlocks(ciphertext, ciphertext)
	padlen := ciphertext[len(ciphertext)-1] + 1 // padlen byte itself
	dec = ciphertext[:len(ciphertext)-int(padlen)]
	return
}

func (t *Tkm) VerifyDecrypt(ike []byte) (nextPayload PayloadType, dec []byte, err error) {
	b := ike[IKE_HEADER_LEN:]
	pHeader := &PayloadHeader{}
	if err = pHeader.Decode(b[:PAYLOAD_HEADER_LENGTH]); err != nil {
		return
	}
	cslen := len(b) - int(pHeader.PayloadLength)
	if cslen != t.suite.macLen {
		err = errors.New("checksum data is not of required length")
		return
	}
	if err = t.VerifyMac(ike); err != nil {
		return
	}
	nextPayload = pHeader.NextPayload
	enc := b[PAYLOAD_HEADER_LENGTH : len(b)-t.suite.macLen]
	// fmt.Printf("enc: \n%s", hex.Dump(enc))
	key := t.skEi
	if t.isInitiator {
		key = t.skEr
	}

	dec, err = t.Decrypt(enc, key)
	// fmt.Printf("dec: \n%s", hex.Dump(dec))
	return
}

func (t *Tkm) EncryptMac(s *Message) (b []byte, err error) {
	key := t.skEr
	if t.isInitiator {
		key = t.skEi
	}
	// encrypt the remaining payloads
	encr, err := t.Encrypt(encodePayloads(s.Payloads), key)
	if err != nil {
		return
	}
	firstPayload := s.Payloads.Array[0].Type()
	// append to new secure payload
	b = append(encodePayloadHeader(firstPayload, uint16(len(encr))), encr...)
	// prepare proper ike header
	s.IkeHeader.MsgLength = uint32(len(b) + IKE_HEADER_LEN + t.suite.macLen)
	// encode and append ike header
	b = append(s.IkeHeader.Encode(), b...)
	// finally attach mac
	macKey := t.skAr
	if t.isInitiator {
		macKey = t.skAi
	}
	b = append(b, t.suite.mac(macKey, b)...)
	return
}

func (t *Tkm) Encrypt(clear, key []byte) (b []byte, err error) {
	iv, err := rand.Prime(rand.Reader, t.suite.ivLen*8) // bits
	if err != nil {
		return
	}
	mode := t.suite.cipher(key, iv.Bytes(), false).(cipher.BlockMode)
	// CBC mode always works in whole blocks.
	if padlen := mode.BlockSize() - len(clear)%mode.BlockSize(); padlen != 0 {
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
	signed := append(signed1, tkm.suite.prf(key, id)...)
	return tkm.suite.prf(tkm.secret, signed)[:tkm.suite.prfLen]
}

func (t *Tkm) IpsecSaCreate(spiI, spiR []byte) {
	plen := t.suite.prfLen
	// KEYMAT = prf+(SK_d, Ni | Nr)
	KEYMAT := t.prfplus(t.skD, append(t.Ni.Bytes(), t.Nr.Bytes()...),
		plen*4)
	t.espEi, t.espAi, t.espEr, t.espAr =
		KEYMAT[0:plen],
		KEYMAT[plen:plen*2],
		KEYMAT[plen*2:plen*3],
		KEYMAT[plen*3:plen*4]
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
