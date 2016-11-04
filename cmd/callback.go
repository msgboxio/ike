package cmd

import (
	"net"

	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/log"
)

// when sending the first packet as initiator, local address is missing
// so it needs to be replaced

type callback struct {
	conn              ike.Conn
	local, remote     net.Addr
	forAdd, forRemove func(*platform.SaParams) error
	forRekeySa        func(session *ike.Session)
}

func saAddr(sa *platform.SaParams, local, remote net.Addr) {
	remoteIP := ike.AddrToIp(remote)
	localIP := ike.AddrToIp(local)
	sa.Ini = remoteIP
	sa.Res = localIP
	if sa.IsInitiator {
		sa.Ini = localIP
		sa.Res = remoteIP
	}
}
func (ret *callback) SendMessage(session *ike.Session, msg *ike.OutgoingMessge) error {
	dest := msg.Addr
	if dest == nil {
		dest = ret.remote
		log.V(2).Infof("send to default addr %s", ret.remote)
	}
	return ret.conn.WritePacket(msg.Data, dest)
}
func (ret *callback) AddSa(session *ike.Session, sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	return ret.forAdd(sa)
}
func (ret *callback) RemoveSa(session *ike.Session, sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	return ret.forRemove(sa)
}
func (ret *callback) RekeySa(session *ike.Session) error {
	ret.forRekeySa(session)
	return nil
}
