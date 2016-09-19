package ike

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/msgboxio/ike/crypto"
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

	Nr, Ni *big.Int

	dhPrivate, DhPublic *big.Int
	DhShared            *big.Int

	Roots *x509.CertPool

	// for debug
	SKEYSEED, KEYMAT []byte

	skD        []byte // further keying material for child sa
	skPi, skPr []byte // used when generating an AUTH
	skAi, skAr []byte // integrity protection keys
	skEi, skEr []byte // encryption keys
}

var ErrorMissingCryptoKeys = errors.New("Missing crypto keys")

func NewTkmInitiator(suite *crypto.CipherSuite, roots *x509.CertPool) (*Tkm, error) {
	tkm := &Tkm{
		suite:       suite,
		isInitiator: true,
		Roots:       roots,
	}
	// standard says nonce shwould be at least half of size of negotiated prf
	ni, err := tkm.ncCreate(suite.Prf.Length * 8)
	if err != nil {
		return nil, err
	}
	tkm.Ni = ni
	// for sending public key
	if _, err := tkm.dhCreate(); err != nil {
		return nil, err
	}
	return tkm, nil
}

func NewTkmResponder(suite *crypto.CipherSuite, no *big.Int, roots *x509.CertPool) (tkm *Tkm, err error) {
	tkm = &Tkm{
		suite: suite,
		Ni:    no,
		Roots: roots,
	}
	// TODO : at least 128 bits & at least half the key size of the negotiated prf
	if nr, err := tkm.ncCreate(no.BitLen()); err != nil {
		return nil, err
	} else {
		tkm.Nr = nr
	}
	if _, err := tkm.dhCreate(); err != nil {
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
	var round = 1
	for len(ret) < bits {
		prev = t.suite.Prf.Apply(key, append(append(prev, data...), byte(round)))
		ret = append(ret, prev...)
		round++
	}
	return ret[:bits]
}

func (t *Tkm) SkeySeedInitial() []byte {
	// SKEYSEED = prf(Ni | Nr, g^ir)
	return t.suite.Prf.Apply(append(t.Ni.Bytes(), t.Nr.Bytes()...), t.DhShared.Bytes())
}

func (t *Tkm) SkeySeedRekey(old_SK_D []byte) []byte {
	// SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
	return t.suite.Prf.Apply(old_SK_D, append(t.DhShared.Bytes(), append(t.Ni.Bytes(), t.Nr.Bytes()...)...))
}

// create ike sa
func (t *Tkm) IsaCreate(spiI, spiR []byte, old_SK_D []byte) {
	// fmt.Printf("key inputs: \nni:\n%snr:\n%sshared:\n%sspii:\n%sspir:\n%s",
	// 	hex.Dump(t.Ni.Bytes()), hex.Dump(t.Nr.Bytes()), hex.Dump(t.DhShared.Bytes()),
	// 	hex.Dump(spiI), hex.Dump(spiR))
	SKEYSEED := []byte{}
	if len(old_SK_D) == 0 {
		SKEYSEED = t.SkeySeedInitial()
	} else {
		SKEYSEED = t.SkeySeedRekey(old_SK_D)
	}
	kmLen := 3*t.suite.Prf.Length + 2*t.suite.KeyLen + 2*t.suite.MacKeyLen
	// KEYMAT =  = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
	KEYMAT := t.prfplus(SKEYSEED,
		append(append(t.Ni.Bytes(), t.Nr.Bytes()...), append(spiI, spiR...)...),
		kmLen)

	// SK_d, SK_pi, and SK_pr MUST be prfLength
	offset := t.suite.Prf.Length
	t.skD = KEYMAT[0:offset]
	t.skAi = KEYMAT[offset : offset+t.suite.MacKeyLen]
	offset += t.suite.MacKeyLen
	t.skAr = KEYMAT[offset : offset+t.suite.MacKeyLen]
	offset += t.suite.MacKeyLen
	t.skEi = KEYMAT[offset : offset+t.suite.KeyLen]
	offset += t.suite.KeyLen
	t.skEr = KEYMAT[offset : offset+t.suite.KeyLen]
	offset += t.suite.KeyLen
	t.skPi = KEYMAT[offset : offset+t.suite.Prf.Length]
	offset += t.suite.Prf.Length
	t.skPr = KEYMAT[offset : offset+t.suite.Prf.Length]

	// for test
	t.KEYMAT = KEYMAT
	t.SKEYSEED = SKEYSEED
	// fmt.Printf("keymat length %d\n", len(KEYMAT))
	// fmt.Printf("skD:\n%sskAi:\n%sskAr:\n%sskEi:\n%sskEr:\n%sskPi:\n%sskPr:\n%s",
	// 	hex.Dump(t.skD),
	// 	hex.Dump(t.skAi),
	// 	hex.Dump(t.skAr),
	// 	hex.Dump(t.skEi),
	// 	hex.Dump(t.skEr),
	// 	hex.Dump(t.skPi),
	// 	hex.Dump(t.skPr))
}

// MAC-then-decrypt
func (t *Tkm) VerifyDecrypt(ike []byte) (dec []byte, err error) {
	skA, skE := t.skAi, t.skEi
	if t.isInitiator {
		skA, skE = t.skAr, t.skEr
	}
	dec, err = t.suite.VerifyDecrypt(ike, skA, skE)
	return
}

func (t *Tkm) CryptoOverhead(b []byte) int {
	return t.suite.Overhead(b)
}

// encrypt-then-MAC
func (t *Tkm) EncryptMac(headers, payload []byte) (b []byte, err error) {
	skA, skE := t.skAr, t.skEr
	if t.isInitiator {
		skA, skE = t.skAi, t.skEi
	}
	if skA == nil || skE == nil {
		return nil, ErrorMissingCryptoKeys
	}
	b, err = t.suite.EncryptMac(headers, payload, skA, skE)
	return
}

func (t *Tkm) IpsecSaCreate(spiI, spiR []byte) (espEi, espAi, espEr, espAr []byte) {
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
	// fmt.Printf("ESP keys :\nEi:\n%sAi:\n%sEr:\n%sAr\n%s",
	// 	hex.Dump(espEi),
	// 	hex.Dump(espAi),
	// 	hex.Dump(espEr),
	// 	hex.Dump(espAr))
	return
}

// SignB gets signed data from tkm
// section 2.15
// For the responder, the octets to be signed
// start with the first octet of the first SPI in the
// header of the second message (IKE_SA_INIT response) and end with the
// last octet of the last payload in the second message.  => initIRB
// Appended to this (for the purposes of computing the signature) are the
// initiator's nonce Ni (just the value, not the payload containing it),
// and the value prf(SK_pr, IDr')
// so signB :=
// responder: initRB | Ni | prf(SK_pr, IDr')
// initiator: initIB | Nr | prf(SK_pi, IDi')
// boolean is important as this method can be used by signer & verifier
func (t *Tkm) SignB(initB []byte, id []byte, forInitiator bool) []byte {
	// ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
	// InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
	key := t.skPr
	nonce := t.Ni
	if forInitiator {
		key = t.skPi
		nonce = t.Nr
	}
	macedID := t.suite.Prf.Apply(key, id)
	signB := append(append(initB, nonce.Bytes()...), macedID...)
	return signB
}

// cert validation
// start vaildating cert chain
func cc_set_user_certficate(cc_id, ri_id, autha_id, CERT []byte) {}

// add remianing certs in chain
func cc_add_certificate(cc_id, autha_id, CERT []byte) {}

// validate
func cc_check_ca(cc_id, ca_id []byte) {}

// after cert validtaion, authenticate peer
func isa_auth(isa_id, cc_id, init_message, AUTH_rem []byte) {}

// create first child sa
func esa_create_first(esa_id, isa_id, sp_id, ea_id, esp_spi_loc, esp_spi_rem []byte) {}
