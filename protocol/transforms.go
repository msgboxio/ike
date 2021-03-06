package protocol

// TransformMap store the configured crypto suite
// NOTE that this cannot be used to parse incoming list of transforms
// incoming list can have many Transforms of same type in 1 proposal
type TransformMap map[TransformType]*SaTransform

func ProposalFromTransform(prot ProtocolID, trs TransformMap, spi []byte) Proposals {
	return Proposals{
		&SaProposal{
			IsLast:     true,
			Number:     1,
			ProtocolID: prot,
			Spi:        append([]byte{}, spi...),
			Transforms: trs.AsList(),
		},
	}
}

// AsList converts transforms to flat list
func (t TransformMap) AsList() (trs []*SaTransform) {
	for _, trsVal := range t {
		trs = append(trs, trsVal)
	}
	return
}

// Within checks if the configured set of transforms occurs within list of proposed transforms
func (t TransformMap) Within(proposed []*SaTransform) bool {
	listHas := func(proposed []*SaTransform, target *SaTransform) bool {
		for _, tr := range proposed {
			if target.IsEqual(tr) {
				return true
			}
		}
		return false
	}
	for _, transform := range t {
		if listHas(proposed, transform) {
			return true
		}
	}
	return false
}

func (t TransformMap) GetType(ty TransformType) *Transform {
	trs, ok := t[ty]
	if !ok {
		return nil
	}
	return &trs.Transform
}

// IkeTransform builds a IKE cipher suite
func IkeTransform(encr EncrTransformId, keyBits uint16, auth AuthTransformId, prf PrfTransformId, dh DhTransformId) TransformMap {
	return TransformMap{
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
func EspTransform(encr EncrTransformId, keyBits uint16, auth AuthTransformId, esn EsnTransformId) TransformMap {
	return TransformMap{
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
