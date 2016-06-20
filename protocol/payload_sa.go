package protocol

import "github.com/msgboxio/log"

// SA payload

func (s *SaPayload) Type() PayloadType {
	return PayloadTypeSA
}
func (s *SaPayload) Encode() (b []byte) {
	for idx, prop := range s.Proposals {
		isLast := idx == len(s.Proposals)-1
		b = append(b, prop.encode(idx+1, isLast)...)
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
