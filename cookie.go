package ike

import (
	"crypto/rand"
	"crypto/sha1"
	stderr "errors"
	"math/big"
	"net"

	"github.com/msgboxio/ike/protocol"
)

// An implementation of COOKIE as specified in
// 2.6. IKE SA SPIs and Cookies

var errMissingCookie = stderr.New("NEED COOKIE")
var errInvalidCookie = stderr.New("INVALID COOKIE")

type peerRequestsCookieError struct {
	Cookie *protocol.NotifyPayload
}

func (e peerRequestsCookieError) Error() string {
	return "Rx Cookie"
}

// Version for COOKIE
var cookieVersion []byte

// Secret for COOKIE
var cookieSecret [64]byte

func init() {
	cookieVersion = []byte{0, 0}
	rand.Read(cookieSecret[:])
}

func getCookie(no *big.Int, spiI []byte, remote net.Addr) []byte {
	// Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
	digest := sha1.New()
	digest.Write(no.Bytes())
	digest.Write(spiI)
	digest.Write(AddrToIp(remote))
	digest.Write(cookieSecret[:])
	return append(cookieVersion, digest.Sum(nil)...)
}
