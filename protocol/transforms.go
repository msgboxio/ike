package protocol

// Transforms store the configured crypto suite
type Transforms map[TransformType]*SaTransform

// AsList converts transforms to flat list
func (configured Transforms) AsList() (trs []*SaTransform) {
	for _, trsVal := range configured {
		trs = append(trs, trsVal)
	}
	return
}

// Within checks if the configured set of transforms occurs within list of porposed transforms
func (configured Transforms) Within(proposals []*SaTransform) bool {
	listHas := func(trsList []*SaTransform, trs *SaTransform) bool {
		for _, tr := range trsList {
			if trs.IsEqual(tr) {
				return true
			}
		}
		return false
	}

	for _, proposal := range configured {
		if !listHas(proposals, proposal) {
			return false
		}
	}
	return true
}

// IkeTransform builds a IKE cipher suite
func IkeTransform(encr EncrTransformId, keyBits uint16, auth AuthTransformId, prf PrfTransformId, dh DhTransformId) Transforms {
	return Transforms{
		TRANSFORM_TYPE_ENCR: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_ENCR,
				TransformId: uint16(encr),
			},
			KeyLength: keyBits,
		},
		TRANSFORM_TYPE_INTEG: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_INTEG,
				TransformId: uint16(auth),
			},
		},
		TRANSFORM_TYPE_PRF: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_PRF,
				TransformId: uint16(prf),
			},
		},
		TRANSFORM_TYPE_DH: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_DH,
				TransformId: uint16(dh),
			},
			IsLast: true,
		},
	}
}

// EspTransform builds an ESP cipher suite
func EspTransform(encr EncrTransformId, keyBits uint16, auth AuthTransformId, esn EsnTransformId) Transforms {
	return Transforms{
		TRANSFORM_TYPE_ENCR: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_ENCR,
				TransformId: uint16(encr),
			}, KeyLength: keyBits},
		TRANSFORM_TYPE_INTEG: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_INTEG,
				TransformId: uint16(auth),
			},
		},
		TRANSFORM_TYPE_ESN: &SaTransform{
			Transform: Transform{
				Type:        TRANSFORM_TYPE_ESN,
				TransformId: uint16(esn),
			},
			IsLast: true,
		},
	}
}
