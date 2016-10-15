package protocol

import "github.com/pkg/errors"

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
				return errors.Wrap(ERR_INVALID_SYNTAX, "SA payload has extra data")
			}
			break
		}
	}
	return
}
