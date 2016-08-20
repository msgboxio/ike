package protocol

import "github.com/msgboxio/packets"

//   Transform Substructure

func decodeAttribute(b []byte) (attr *TransformAttribute, used int, err error) {
	if len(b) < MIN_LEN_ATTRIBUTE {
		err = ErrF(ERR_INVALID_SYNTAX, "attribute too small %d < %d", len(b), MIN_LEN_ATTRIBUTE)
		return
	}
	if at, _ := packets.ReadB16(b, 0); AttributeType(at&0x7fff) != ATTRIBUTE_TYPE_KEY_LENGTH {
		err = ErrF(ERR_INVALID_SYNTAX, "wrong attribute type, 0x%x", at)
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
		err = ErrF(ERR_INVALID_SYNTAX, "transform too small %d < %d", len(b), MIN_LEN_TRANSFORM)
		return
	}
	trans = &SaTransform{}
	if last, _ := packets.ReadB8(b, 0); last == 0 {
		trans.IsLast = true
	}
	trLength, _ := packets.ReadB16(b, 2)
	if len(b) < int(trLength) {
		err = ErrF(ERR_INVALID_SYNTAX, "transform too small %d < %d", len(b), int(trLength))
		return
	}
	if int(trLength) < MIN_LEN_TRANSFORM {
		err = ErrF(ERR_INVALID_SYNTAX, "transform too small %d < %d", int(trLength), MIN_LEN_TRANSFORM)
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

func (trans *SaTransform) encode(isLast bool) (b []byte) {
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

func (tr *SaTransform) IsEqual(other *SaTransform) bool {
	if tr == nil || other == nil {
		return false
	}
	if tr.KeyLength != other.KeyLength {
		return false
	}
	if tr.Transform.Type != other.Transform.Type {
		return false
	}
	if tr.Transform.TransformId != other.Transform.TransformId {
		return false
	}
	return true
}
