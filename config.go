package ike

type ClientCfg struct {
	IkeTransforms, EspTransforms []*SaTransform

	IkeSpiI, IkeSpiR Spi

	EspSpiI, EspSpiR []byte

	ProposalIke, ProposalEsp *SaProposal

	TsI, TsR []*Selector
}

var (
	IKE_AES_CBC_SHA1_96_DH_1024 = []*SaTransform{
		&SaTransform{Transform: _ENCR_AES_CBC, KeyLength: 128},
		&SaTransform{Transform: _PRF_HMAC_SHA1},
		&SaTransform{Transform: _AUTH_HMAC_SHA1_96},
		&SaTransform{Transform: _MODP_1024, IsLast: true},
	}

	IKE_CAMELLIA_CBC_SHA2_256_128_DH_2048 = []*SaTransform{
		&SaTransform{Transform: _ENCR_CAMELLIA_CBC, KeyLength: 128},
		&SaTransform{Transform: _PRF_HMAC_SHA2_256},
		&SaTransform{Transform: _AUTH_HMAC_SHA2_256_128},
		&SaTransform{Transform: _MODP_2048, IsLast: true},
	}

	ESP_AES_CBC_SHA1_96 = []*SaTransform{
		&SaTransform{Transform: _ENCR_AES_CBC, KeyLength: 128},
		&SaTransform{Transform: _AUTH_HMAC_SHA1_96},
		&SaTransform{Transform: _NO_ESN, IsLast: true},
	}

	ESP_CAMELLIA_CBC_SHA2_256_128 = []*SaTransform{
		&SaTransform{Transform: _ENCR_CAMELLIA_CBC, KeyLength: 128},
		&SaTransform{Transform: _AUTH_HMAC_SHA2_256_128},
		&SaTransform{Transform: _ESN, IsLast: true},
	}
)
