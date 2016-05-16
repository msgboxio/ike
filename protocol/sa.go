package protocol

import (
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

// SA payload

//   Proposal Substructure

func (prop *SaProposal) IsSpiSizeCorrect(spiSize int) bool {
	switch prop.ProtocolId {
	case IKE:
		if spiSize == 8 {
			return true
		}
	case ESP, AH:
		if spiSize == 4 {
			return true
		}
	}
	return false
}

func decodeProposal(b []byte) (prop *SaProposal, used int, err error) {
	if len(b) < MIN_LEN_PROPOSAL {
		log.V(LOG_CODEC_ERR).Infof("proposal too small %d < %d", len(b), MIN_LEN_PROPOSAL)
		err = ERR_INVALID_SYNTAX
		return
	}
	prop = &SaProposal{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		prop.IsLast = true
	}
	propLength, _ := packets.ReadB16(b, 2)
	prop.Number, _ = packets.ReadB8(b, 4)
	pId, _ := packets.ReadB8(b, 5)
	prop.ProtocolId = ProtocolId(pId)
	spiSize, _ := packets.ReadB8(b, 6)
	numTransforms, _ := packets.ReadB8(b, 7)
	// variable parts
	// spi
	used = MIN_LEN_PROPOSAL + int(spiSize)
	if len(b) < used {
		log.V(LOG_CODEC_ERR).Infof("proposal length too small %d < %d", len(b), used)
		err = ERR_INVALID_SYNTAX
		return
	}
	prop.Spi = append([]byte{}, b[MIN_LEN_PROPOSAL:used]...)
	// proposal
	if (int(propLength) < MIN_LEN_PROPOSAL) ||
		(int(propLength) < used) {
		log.V(LOG_CODEC_ERR).Infof("proposal length too small %d < %d", propLength, MIN_LEN_PROPOSAL)
		err = ERR_INVALID_SYNTAX
		return
	}
	if len(b) < int(propLength) {
		log.V(LOG_CODEC_ERR).Infof("invalid length of proposal %d < %d", len(b), used+int(propLength))
		err = ERR_INVALID_SYNTAX
		return
	}
	b = b[used:int(propLength)]
	for len(b) > 0 {
		trans, usedT, errT := decodeTransform(b)
		if errT != nil {
			err = errT
			return
		}
		prop.SaTransforms = append(prop.SaTransforms, trans)
		b = b[usedT:]
		if trans.IsLast {
			if len(b) > 0 {
				log.V(LOG_CODEC_ERR).Infof("Extra bytes at end of proposal: %d", len(b))
				err = ERR_INVALID_SYNTAX
				return
			}
			break
		}
	}
	if len(prop.SaTransforms) != int(numTransforms) {
		log.V(LOG_CODEC_ERR).Infof("Incorrect number of transforms: %d != %d",
			len(prop.SaTransforms), numTransforms)
		err = ERR_INVALID_SYNTAX
		return
	}
	used = int(propLength)
	return
}

func encodeProposal(prop *SaProposal, number int, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_PROPOSAL)
	if !isLast {
		packets.WriteB8(b, 0, 2)
	}
	packets.WriteB8(b, 4, prop.Number)
	packets.WriteB8(b, 5, uint8(prop.ProtocolId))
	packets.WriteB8(b, 6, uint8(len(prop.Spi)))
	packets.WriteB8(b, 7, uint8(len(prop.SaTransforms)))
	b = append(b, prop.Spi...)
	var isLastTr bool
	for idx, tr := range prop.SaTransforms {
		if idx == len(prop.SaTransforms)-1 {
			isLastTr = true
		}
		b = append(b, encodeTransform(tr, isLastTr)...)
	}
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

//   Transform Substructure

func decodeAttribute(b []byte) (attr *TransformAttribute, used int, err error) {
	if len(b) < MIN_LEN_ATTRIBUTE {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if at, _ := packets.ReadB16(b, 0); AttributeType(at&0x7fff) != ATTRIBUTE_TYPE_KEY_LENGTH {
		log.V(LOG_CODEC_ERR).Infof("wrong attribute type, 0x%x", at)
		err = ERR_INVALID_SYNTAX
		return
	}
	alen, _ := packets.ReadB16(b, 2)
	attr = &TransformAttribute{
		Type:  ATTRIBUTE_TYPE_KEY_LENGTH,
		Value: alen,
	}
	used = 4
	return
}

func decodeTransform(b []byte) (trans *SaTransform, used int, err error) {
	if len(b) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trans = &SaTransform{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		trans.IsLast = true
	}
	trLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(trLength) {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	if int(trLength) < MIN_LEN_TRANSFORM {
		log.V(LOG_CODEC_ERR).Info("")
		err = ERR_INVALID_SYNTAX
		return
	}
	trType, _ := packets.ReadB8(b, 4)
	trans.Transform.Type = TransformType(trType)
	trans.Transform.TransformId, _ = packets.ReadB16(b, 6)
	// variable parts
	b = b[MIN_LEN_TRANSFORM:int(trLength)]
	attrs := make(map[AttributeType]*TransformAttribute)
	for len(b) > 0 {
		attr, attrUsed, attrErr := decodeAttribute(b)
		if attrErr != nil {
			err = attrErr
			return
		}
		b = b[attrUsed:]
		attrs[attr.Type] = attr
	}
	if at, ok := attrs[ATTRIBUTE_TYPE_KEY_LENGTH]; ok {
		trans.KeyLength = at.Value
	}
	used = int(trLength)
	return
}

func encodeTransform(trans *SaTransform, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_TRANSFORM)
	if !isLast {
		packets.WriteB8(b, 0, 3)
	}
	packets.WriteB8(b, 4, uint8(trans.Transform.Type))
	packets.WriteB16(b, 6, trans.Transform.TransformId)
	if trans.KeyLength != 0 {
		// TODO - taken a shortcut for attribute
		attr := make([]byte, 4)
		packets.WriteB16(attr, 0, 0x8000|14) // key length in bits
		packets.WriteB16(attr, 2, trans.KeyLength)
		b = append(b, attr...)
	}
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}

// payload

func (s *SaPayload) Type() PayloadType {
	return PayloadTypeSA
}
func (s *SaPayload) Encode() (b []byte) {
	for idx, prop := range s.Proposals {
		var isLast bool
		if idx == len(s.Proposals)-1 {
			isLast = true
		}
		b = append(b, encodeProposal(prop, idx+1, isLast)...)
	}
	return
}
func (s *SaPayload) Decode(b []byte) (err error) {
	// Header has already been decoded
	for len(b) > 0 {
		prop, used, errP := decodeProposal(b)
		if errP != nil {
			return errP
		}
		s.Proposals = append(s.Proposals, prop)
		b = b[used:]
		if prop.IsLast {
			if len(b) > 0 {
				log.V(LOG_CODEC_ERR).Info("")
				err = ERR_INVALID_SYNTAX
				return
			}
			break
		}
	}
	return
}
