package ike

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"

	"github.com/msgboxio/ike/protocol"
)

type CookieError struct {
	Cookie *protocol.NotifyPayload
}

func (e CookieError) Error() string {
	return "Rx Cookie"
}

var MissingCookieError = errors.New("Missing COOKIE")

// Version for COOKIE
var cookieVersion []byte

// Secret for COOKIE
var cookieSecret [64]byte

func init() {
	cookieVersion = []byte{0, 0}
	rand.Read(cookieSecret[:])
}

func getCookie(initI *Message) []byte {
	// Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
	digest := sha1.New()
	no := initI.Payloads.Get(protocol.PayloadTypeNonce).(*protocol.NoncePayload)
	digest.Write(no.Nonce.Bytes())
	digest.Write(initI.IkeHeader.SpiI)
	digest.Write(AddrToIp(initI.RemoteAddr))
	digest.Write(cookieSecret[:])
	return append(cookieVersion, digest.Sum(nil)...)
}
