package ike

import (
	"bytes"
	"net"

	"msgbox.io/log"
	"msgbox.io/packets"
)

type ClientCfg struct {
	ikeTransforms, espTransforms []*SaTransform

	ikeSpiI, ikeSpiR Spi
	EspSpi           []byte

	proposalIke, proposalEsp *SaProposal

	TsI, TsR []*Selector
}

func NewClientCfg() *ClientCfg {
	ikeSpiI := MakeSpi()
	espSpi := MakeSpi()
	ikeTransforms := []*SaTransform{
		// &SaTransform{Transform: _ENCR_CAMELLIA_CBC, KeyLength: 128},
		&SaTransform{Transform: _ENCR_AES_CBC, KeyLength: 128},
		// &SaTransform{Transform: _PRF_HMAC_SHA2_256},
		&SaTransform{Transform: _PRF_HMAC_SHA1},
		// &SaTransform{Transform: _AUTH_HMAC_SHA2_256_128},
		&SaTransform{Transform: _AUTH_HMAC_SHA1_96},
		// &SaTransform{Transform: _MODP_2048, IsLast: true},
		&SaTransform{Transform: _MODP_1024, IsLast: true},
	}
	espTransforms := []*SaTransform{
		// &SaTransform{Transform: _ENCR_CAMELLIA_CBC, KeyLength: 128},
		&SaTransform{Transform: _ENCR_AES_CBC, KeyLength: 128},
		&SaTransform{Transform: _AUTH_HMAC_SHA1_96},
		&SaTransform{Transform: _NO_ESN, IsLast: true},
	}
	return &ClientCfg{
		ikeSpiI:       ikeSpiI,
		EspSpi:        espSpi[:4],
		ikeTransforms: ikeTransforms,
		espTransforms: espTransforms,
		proposalIke: &SaProposal{
			Number:     1,
			ProtocolId: IKE,
			Spi:        ikeSpiI[:],
			Transforms: ikeTransforms,
		},
		proposalEsp: &SaProposal{
			IsLast:     true,
			Number:     2,
			ProtocolId: ESP,
			Spi:        espSpi[:4],
			Transforms: espTransforms,
		},
		TsI: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
		TsR: []*Selector{&Selector{
			Type:         TS_IPV4_ADDR_RANGE,
			IpProtocolId: 0,
			StartPort:    0,
			Endport:      65535,
			StartAddress: net.IPv4(0, 0, 0, 0).To4(),
			EndAddress:   net.IPv4(255, 255, 255, 255).To4(),
		}},
	}
}

func RunClient(remote *net.UDPAddr) {
	// env := make(map[Spi]*Tkm)
	udp, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		log.Fatal(err)
	}
	cfg := NewClientCfg()
	suite := NewCipherSuite(cfg.ikeTransforms)
	tkm, err := NewTkmInitiator(suite)
	if err != nil {
		log.Fatal(err)
	}
	// send IKE_SA_INIT
	ikeProposals := []*SaProposal{cfg.proposalIke}
	initI := MakeInit(cfg.ikeSpiI, Spi{}, ikeProposals, tkm)
	initIb, err := EncodeTx(initI, tkm, udp, remote, true)
	if err != nil {
		log.Fatal(err)
	}

	initR, initRb, _, err := RxDecode(nil, udp, remote)
	if err != nil {
		log.Fatal(err)
	}
	if !EnsurePayloads(initR, InitPayloads) {
		log.Fatal("essential payload is missing from init message")
	}
	if !bytes.Equal(initR.IkeHeader.SpiI[:], cfg.ikeSpiI[:]) {
		log.Fatal("received different spi from peer")
	}
	// TODO - ensure sa parameters are same
	// initialize dh shared with their public key
	keR := initR.Payloads.Get(PayloadTypeKE).(*KePayload)
	if err := tkm.DhGenerateKey(keR.KeyData); err != nil {
		log.Fatal(err)
	}
	// set Nr
	no := initR.Payloads.Get(PayloadTypeNonce).(*NoncePayload)
	tkm.Nr = no.Nonce
	// create rest of ike sa
	spiI, spiR := initR.IkeHeader.SpiI, initR.IkeHeader.SpiR
	tkm.IsaCreate(spiI[:], spiR[:])
	tkm.SetSecret([]byte("ak@msgbox.io"), []byte("foo"))

	// auth
	signed1 := append(initIb, tkm.Nr.Bytes()...)
	espProposals := []*SaProposal{cfg.proposalEsp}
	authI := MakeAuth(spiI, spiR, espProposals, cfg.TsI, cfg.TsR, signed1, tkm)

	if _, err := EncodeTx(authI, tkm, udp, remote, true); err != nil {
		log.Fatal(err)
	}

	authR, _, _, err := RxDecode(tkm, udp, remote)
	if err != nil {
		log.Fatal(err)
	}
	if !EnsurePayloads(authR, AuthRPayloads) {
		log.Fatal("essential payload is missing from auth message")
	}
	if !authenticateR(authR, initRb, tkm) {
		log.Fatal("could not authenticate")
	}
	spi, _ := packets.ReadB32(cfg.EspSpi, 0)
	log.Infof("sa Established: %x", spi)
}
