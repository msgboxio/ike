package ike

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"msgbox.io/ike/crypto"
	"msgbox.io/ike/protocol"
	"msgbox.io/packets"
)

func TestTkm(t *testing.T) {
	no := `63a02b62475680de1c50af97a82a7abd8d464d9511f87ac86a3e1e4217405afa`
	shared := `327adb6c8f7185d4897b652861f5474f8e7be3882853093029d15747645cae97be69b476e0a11a12d03ea6d6ebabc51aedc7c66399b6c7d6a2e3da2b087834762e0ca23ede6a9a0a6948e8291a13969c9be0961eff40c06700c279cb99983e1f22ddba4ead1c2cd180832b534e0bfe5a2a3d4210d721efb1868b555e1912e98133c0b690abfd16e0e5d01c99c73934c380aa7c2363179069d2c8abfc061a1107e9cfa40ce3735258fcf81456bff7edc2bd63b99e2c32ff6ec33f2552b80ce870f3d268d47c72ef61c8c9e8ebe975e7012f8b79a75b2ddf914048c69b169c2f67a816c276fb1dff11fcc63e883a51505baecfb581ab375534b52d43e441996089`

	Nonce, ok := new(big.Int).SetString(no, 16)
	if !ok {
		t.Fatal(1)
	}
	NonceO, ok := new(big.Int).SetString(no, 16)
	if !ok {
		t.Fatal(2)
	}
	DhShared, ok := new(big.Int).SetString(shared, 16)
	if !ok {
		t.Fatal(3)
	}

	transforms := []*protocol.SaTransform{
		&protocol.SaTransform{Transform: _ENCR_CAMELLIA_CBC},
		&protocol.SaTransform{Transform: _AUTH_HMAC_SHA2_256_128},
		&protocol.SaTransform{Transform: _MODP_2048},
		&protocol.SaTransform{Transform: _PRF_HMAC_SHA2_256},
	}
	tkm := &Tkm{
		suite:       crypto.NewCipherSuite(transforms),
		isInitiator: false,
		Ni:          Nonce,
		Nr:          NonceO,
		DhShared:    DhShared,
	}
	if tkm.suite == nil {
		t.Fatal(4)
	}
	spiI, _ := hex.DecodeString("928f3f581f05a563")
	tkm.IsaCreate(spiI, []byte{})

	_sk := `ff7972ddae0b6d10ea4fd33418a489a4c92e8b053e25b4c9166b4b7a2aa29776`
	sk, _ := hex.DecodeString(_sk)
	if !bytes.Equal(tkm.SKEYSEED, sk) {
		t.Fatalf("\n%s\nvs\n%s", hex.Dump(tkm.SKEYSEED), hex.Dump(sk))
	}

	_km := `dda4d24404d5e03911079e67e56b12e47523972bf0cc75df8e13e79ed23607d3dc28758b9ea4a67c9bcd6260cc83cc1baa77d4ff2fee910e36826c66b6af9d091c54dc63e8318df0fde5e6acd7d175cf354d6b169217b662041f9b401751c7ce94c01e11830e9bbeb3b7c24ae58f79260b2220dfe4220dc64a79bb215a778734c9bbce70166a82422715e7b11620d92af5fdbbee31bebc90be909b08a5e810ad979a16584cd32c61682ccfb0d30822a60ccf1909994472f90a3b925c7bb4c1664abe17463a429fbb94bade006b05855011425e6155c87907b21560b99e962455`
	km, _ := hex.DecodeString(_km)
	if !bytes.Equal(tkm.KEYMAT, km) {
		t.Fatalf("\n%s\nvs\n%s", hex.Dump(tkm.KEYMAT), hex.Dump(km))
	}

	_signed_encr := `928f3f58 1f05a563 00000000 00000000 2e202308 00000001 000000e0 230000c4 fcbb4a7a 26d6a66d 41d372ec d4cfaef3 c2454434 a1d96704 2f87cef5 0ea8b816 d455a55a 7a634485 4662f63e 514b0673 c8a4aff7 06d32a11 117f0820 50c8caed cc31b4da d69666f4 53554517 32d7113a 6cd19af9 2ef90fdc 44c84ec7 c1684f1d 03a2ef97 668b8073 3fa97831 9692e726 cf7257fc 6cbfd69a c9f84114 2d05111b b584e65f 08258237 5910ca0b c2598a65 8c9e474a 9f25f0ae e918410b 6eadd04f c35fa123 9f85456a ba42471e 37d02205 e2516ae1 95b67260 a0a34127 ed3c59d6`
	signed_encr := packets.Hexit(_signed_encr).Bytes()
	if _, err := tkm.VerifyDecrypt(signed_encr); err != nil {
		t.Fatal(err)
	}
}
