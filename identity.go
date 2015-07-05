package ike

type Identities interface {
	ForAuthentication(IdType) []byte
	AuthData(id []byte, method AuthMethod) []byte
}

type PskIdentities struct {
	Ids     map[string][]byte
	Primary string
}

func (psk PskIdentities) ForAuthentication(idType IdType) []byte {
	if idType != ID_RFC822_ADDR {
		return nil
	}
	return []byte(psk.Primary)
}

func (psk PskIdentities) AuthData(id []byte, method AuthMethod) []byte {
	if method != SHARED_KEY_MESSAGE_INTEGRITY_CODE {
		return nil
	}
	if d, ok := psk.Ids[string(id)]; ok {
		return d
	}
	return nil
}
