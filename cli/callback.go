package cli

import (
	"net"

	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
)

// when sending the first packet as initiator, local address is missing
// so it needs to be replaced

type callback struct {
	conn              ike.Conn
	local, remote     net.Addr
	forAdd, forRemove func(*platform.SaParams) error
	forRekeySa        func(session *ike.Session)
}

func (c *callback) setAddresses(local, remote net.Addr) {
	c.local = local
	c.remote = remote
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
	}
	return ret.conn.WritePacket(msg.Data, dest)
}
func (ret *callback) IkeAuth(session *ike.Session, err error) {
	if err == nil {
		session.Logger.Info("New IKE SA: ", session)
	} else {
		session.Logger.Warningf("IKE SA FAILED: %+v", err)
	}
}
func (ret *callback) AddSa(session *ike.Session, sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	err := ret.forAdd(sa)
	session.Logger.Infof("Installed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
func (ret *callback) RemoveSa(session *ike.Session, sa *platform.SaParams) error {
	saAddr(sa, ret.local, ret.remote)
	err := ret.forRemove(sa)
	session.Logger.Infof("Removed Child SA: %#x<=>%#x; [%s]%s<=>%s[%s] err: %v",
		sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res, err)
	return err
}
func (ret *callback) RekeySa(session *ike.Session) error {
	ret.forRekeySa(session)
	return nil
}
