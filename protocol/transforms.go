package protocol

var (
	T_ENCR_AES_CTR      = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(ENCR_AES_CTR)}
	T_ENCR_AES_CBC      = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(ENCR_AES_CBC)}
	T_ENCR_CAMELLIA_CBC = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(ENCR_CAMELLIA_CBC)}
	T_ENCR_CAMELLIA_CTR = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(ENCR_CAMELLIA_CTR)}
	T_ENCR_NULL         = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(ENCR_NULL)}

	T_AEAD_AES_GCM_16        = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(AEAD_AES_GCM_16)}
	T_AEAD_CHACHA20_POLY1305 = Transform{Type: TRANSFORM_TYPE_ENCR, TransformId: uint16(AEAD_CHACHA20_POLY1305)}

	T_PRF_AES128_XCBC   = Transform{Type: TRANSFORM_TYPE_PRF, TransformId: uint16(PRF_AES128_XCBC)}
	T_PRF_HMAC_SHA1     = Transform{Type: TRANSFORM_TYPE_PRF, TransformId: uint16(PRF_HMAC_SHA1)}
	T_PRF_HMAC_SHA2_256 = Transform{Type: TRANSFORM_TYPE_PRF, TransformId: uint16(PRF_HMAC_SHA2_256)}
	T_PRF_HMAC_SHA2_384 = Transform{Type: TRANSFORM_TYPE_PRF, TransformId: uint16(PRF_HMAC_SHA2_384)}
	T_PRF_HMAC_SHA2_512 = Transform{Type: TRANSFORM_TYPE_PRF, TransformId: uint16(PRF_HMAC_SHA2_512)}

	T_AUTH_AES_XCBC_96       = Transform{Type: TRANSFORM_TYPE_INTEG, TransformId: uint16(AUTH_AES_XCBC_96)}
	T_AUTH_HMAC_SHA1_96      = Transform{Type: TRANSFORM_TYPE_INTEG, TransformId: uint16(AUTH_HMAC_SHA1_96)}
	T_AUTH_HMAC_SHA2_256_128 = Transform{Type: TRANSFORM_TYPE_INTEG, TransformId: uint16(AUTH_HMAC_SHA2_256_128)}
	T_AUTH_HMAC_SHA2_384_192 = Transform{Type: TRANSFORM_TYPE_INTEG, TransformId: uint16(AUTH_HMAC_SHA2_384_192)}
	T_AUTH_HMAC_SHA2_512_256 = Transform{Type: TRANSFORM_TYPE_INTEG, TransformId: uint16(AUTH_HMAC_SHA2_512_256)}

	T_MODP_1024 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_1024)}
	T_MODP_1536 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_1536)}
	T_MODP_2048 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_2048)}
	T_MODP_3072 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_3072)}
	T_MODP_4096 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_4096)}
	T_MODP_6144 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_6144)}
	T_MODP_8192 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(MODP_8192)}

	T_ECP_224 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(ECP_224)}
	T_ECP_256 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(ECP_256)}
	T_ECP_384 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(ECP_384)}
	T_ECP_521 = Transform{Type: TRANSFORM_TYPE_DH, TransformId: uint16(ECP_521)}

	T_ESN    = Transform{Type: TRANSFORM_TYPE_ESN, TransformId: uint16(ESN)}
	T_NO_ESN = Transform{Type: TRANSFORM_TYPE_ESN, TransformId: uint16(ESN_NONE)}
)

type Transforms map[TransformType]*SaTransform

var (
	IKE_AES_CBC_SHA1_96_MODP1024 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_PRF:   &SaTransform{Transform: T_PRF_HMAC_SHA1},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA1_96},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_1024, IsLast: true},
	}
	IKE_AES_CBC_SHA256_MODP2048 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_PRF:   &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_2048, IsLast: true},
	}
	IKE_AES_CBC_SHA256_MODP3072 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_PRF:   &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_3072, IsLast: true},
	}

	IKE_AES_CBC_SHA256_ECP256 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_PRF:   &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_ECP_256, IsLast: true},
	}

	// key length is set to 128b
	// 16B icv
	IKE_AES_GCM_16_MODP2048 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_AEAD_AES_GCM_16, KeyLength: 128}, // AEAD_AES_128_GCM
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_PRF_HMAC_SHA1},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_2048, IsLast: true},
	}
	IKE_AES_GCM_16_MODP3072 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_AEAD_AES_GCM_16, KeyLength: 128}, // AEAD_AES_128_GCM
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_PRF_HMAC_SHA1},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_3072, IsLast: true},
	}

	IKE_AES128GCM16_PRFSHA256_ECP256 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_AEAD_AES_GCM_16, KeyLength: 128}, // AEAD_AES_128_GCM
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_ECP_256, IsLast: true},
	}

	IKE_AES256GCM16_PRFSHA384_ECP384 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_AEAD_AES_GCM_16, KeyLength: 256}, // AEAD_AES_256_GCM
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_PRF_HMAC_SHA2_384},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_ECP_384, IsLast: true},
	}

	IKE_CHACHA20POLY1305_PRFSHA256_ECP256 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_AEAD_CHACHA20_POLY1305, KeyLength: 256},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_ECP_256, IsLast: true},
	}

	IKE_CAMELLIA_CBC_SHA2_256_128_MODP2048 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_CAMELLIA_CBC, KeyLength: 128},
		TRANSFORM_TYPE_PRF:   &SaTransform{Transform: T_PRF_HMAC_SHA2_256},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_DH:    &SaTransform{Transform: T_MODP_2048, IsLast: true},
	}
)

var (
	ESP_AES_CBC_SHA1_96 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA1_96},
		TRANSFORM_TYPE_ESN:   &SaTransform{Transform: T_NO_ESN, IsLast: true},
	}
	ESP_AES_CBC_SHA2_256 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_AES_CBC, KeyLength: 128},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_ESN:   &SaTransform{Transform: T_NO_ESN, IsLast: true},
	}

	// key length is set to 128
	// This is due to lack of support for 256b keys in older kernels (Jessie)
	ESP_AES_GCM_16 = Transforms{
		TRANSFORM_TYPE_ENCR: &SaTransform{Transform: T_AEAD_AES_GCM_16, KeyLength: 128},
		TRANSFORM_TYPE_ESN:  &SaTransform{Transform: T_NO_ESN, IsLast: true},
	}

	ESP_CHACHA20POLY1305 = Transforms{
		TRANSFORM_TYPE_ENCR: &SaTransform{Transform: T_AEAD_CHACHA20_POLY1305, KeyLength: 256},
		TRANSFORM_TYPE_ESN:  &SaTransform{Transform: T_NO_ESN, IsLast: true},
	}

	ESP_NULL_SHA1_96 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_NULL},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA1_96},
		TRANSFORM_TYPE_ESN:   &SaTransform{Transform: T_NO_ESN, IsLast: true},
	}

	ESP_CAMELLIA_CBC_SHA2_256_128 = Transforms{
		TRANSFORM_TYPE_ENCR:  &SaTransform{Transform: T_ENCR_CAMELLIA_CBC, KeyLength: 128},
		TRANSFORM_TYPE_INTEG: &SaTransform{Transform: T_AUTH_HMAC_SHA2_256_128},
		TRANSFORM_TYPE_ESN:   &SaTransform{Transform: T_ESN, IsLast: true},
	}
)

func listHas(trsList []*SaTransform, trs *SaTransform) bool {
	for _, tr := range trsList {
		if trs.IsEqual(tr) {
			return true
		}
	}
	return false
}

func (configured Transforms) AsList() (trs []*SaTransform) {
	for _, trsVal := range configured {
		trs = append(trs, trsVal)
	}
	return
}

// checks if the configured set of transforms occurs within list of porposed transforms
func (configured Transforms) Within(proposals []*SaTransform) bool {
	for _, proposal := range configured {
		if !listHas(proposals, proposal) {
			return false
		}
	}
	return true
}
