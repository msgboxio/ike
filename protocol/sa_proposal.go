package protocol

import (
	"github.com/msgboxio/log"
	"github.com/msgboxio/packets"
)

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

func (prop *SaProposal) encode(number int, isLast bool) (b []byte) {
	b = make([]byte, MIN_LEN_PROPOSAL)
	if !isLast {
		packets.WriteB8(b, 0, 2)
	}
	packets.WriteB8(b, 4, prop.Number)
	packets.WriteB8(b, 5, uint8(prop.ProtocolId))
	packets.WriteB8(b, 6, uint8(len(prop.Spi)))
	packets.WriteB8(b, 7, uint8(len(prop.SaTransforms)))
	b = append(b, prop.Spi...)
	for idx, tr := range prop.SaTransforms {
		isLast := idx == len(prop.SaTransforms)-1
		b = append(b, tr.encode(isLast)...)
	}
	packets.WriteB16(b, 2, uint16(len(b)))
	return
}
