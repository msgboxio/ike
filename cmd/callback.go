package cmd

import (
	cxt "context"
	"net"

	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/log"
)

type callback struct {
	conn          ike.Conn
	local, remote net.Addr
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
func (ret *callback) SendMessage(msg *ike.OutgoingMessge) error {
	dest := msg.Addr
	if dest == nil {
		dest = ret.remote
		log.Infof("send to default addr %s", ret.remote)
	}
	return ret.conn.WritePacket(msg.Data, dest)
}
func (ret *callback) AddSa(sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	log.Infof("Installing Child SA: %#x<=>%#x; [%s]%s<=>%s[%s]",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res)
	err := platform.InstallChildSa(sa)
	log.Info("Installed Child SA; error:", err)
	return err
}
func (ret *callback) RemoveSa(sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	err := platform.RemoveChildSa(sa)
	log.Info("Removed child SA")
	return err
}
func (ret *callback) NewSa(session *ike.Session) error {
	log.Info("NEW SA NEEDED")
	session.Close(cxt.DeadlineExceeded)
	return nil
}

// when sending the first packet as initiator, local address is missing
// so it needs to be replaced
func ikeCallback(_conn ike.Conn, _local, _remote net.Addr) ike.Callback {
	// callback will run within session's goroutine
	return &callback{
		local:  _local,
		remote: _remote,
		conn:   _conn,
	}
}
