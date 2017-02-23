package ike

import (
	"context"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
)

type IkeCmd struct {
	// map of initiator spi -> session
	sessions, initiators Sessions
	conn                 Conn
	cb                   SessionCallback
}

func NewCmd(conn Conn, cb SessionCallback) *IkeCmd {
	return &IkeCmd{
		sessions:   NewSessions(),
		initiators: NewSessions(),
		conn:       conn,
		cb:         cb,
	}
}

func (i *IkeCmd) AddSa(sa *platform.SaParams) error {
	return i.cb.AddSa(nil, sa)
}
func (i *IkeCmd) RemoveSa(sa *platform.SaParams) error {
	return i.cb.RemoveSa(nil, sa)
}

// dont call cb.onError
func (i *IkeCmd) onError(session *Session, err error) {
	// break before make
	if err == ErrorRekeyRequired {
		session.Close(context.DeadlineExceeded)
	} else {
		session.Close(context.Canceled)
	}
}

// newSession handles IKE_SA_INIT requests & replies
func (i *IkeCmd) newSession(msg *Message, pconn Conn, config *Config, log *logrus.Logger) (*Session, error) {
	spi := SpiToInt64(msg.IkeHeader.SpiI)
	// check if this is a IKE_SA_INIT response
	session, found := i.initiators.Get(spi)
	if found {
		// TODO - check if we already have a connection to this host
		// close the initiator session if we do
		// check if incoming message is an acceptable Init Response
		if err := CheckInitResponseForSession(session, msg); err != nil {
			if ce, ok := err.(CookieError); ok {
				// session is always returned for CookieError
				session.SetCookie(ce.Cookie)
				// send packet with Cookie
				session.SendInit()
				return nil, err
			}
			log.Warning("drop packet: ", err)
			// return error
			return nil, err
		}
		// rewrite LocalAddr
		session.SetAddresses(msg.LocalAddr, msg.RemoteAddr)
		// remove from initiators map
		i.initiators.Remove(spi)
	} else {
		// is it a IKE_SA_INIT req ?
		if err := CheckInitRequest(config, msg); err != nil {
			// handle errors that need reply: COOKIE or DH
			if reply := InitErrorNeedsReply(msg, config, err); reply != nil {
				data, err := reply.Encode(nil, false, log)
				if err != nil {
					log.Errorf("error encoding init reply %+v", err)
				}
				pconn.WritePacket(data, msg.RemoteAddr)
			}
			// dont create a new session
			return nil, err
		}
		// create and run session
		sd := &SessionData{
			Conn:   i.conn,
			Local:  msg.LocalAddr,
			Remote: msg.RemoteAddr,
			Cb:     i.cb,
		}
		var err error
		session, err = NewResponder(config, sd, msg, log)
		if err != nil {
			return nil, err
		}
		go func() {
			errS := RunSession(session)
			// wait for session to finish
			i.sessions.Remove(spi)
			session.Logger.Infof("Removed IKE SA: %s", errS)
		}()
	}
	// host based selectors can be added directly since both addresses are available
	loc := AddrToIp(msg.LocalAddr)
	rem := AddrToIp(msg.RemoteAddr)
	if err := session.AddHostBasedSelectors(loc, rem); err != nil {
		log.Warningf("could not add selectors for %s=>%s %s", loc, rem, err)
		return nil, err
	}
	i.sessions.Add(spi, session)
	return session, nil
}

// runs on main goroutine
func (i *IkeCmd) processPacket(msg *Message, config *Config, log *logrus.Logger) {
	// convert spi to uint64 for map lookup
	spi := SpiToInt64(msg.IkeHeader.SpiI)
	// check if a session exists
	session, found := i.sessions.Get(spi)
	if !found {
		var err error
		session, err = i.newSession(msg, i.conn, config, log)
		if err != nil {
			return
		}
	}
	session.PostMessage(msg)
}

// RunInitiator starts & watches over on initiator session
func (i *IkeCmd) RunInitiator(remoteAddr net.Addr, config *Config, log *logrus.Logger) {
	go func() {
		for { // restart conn
			sd := &SessionData{
				Conn:   i.conn,
				Remote: remoteAddr,
				Cb:     i.cb,
			}
			initiator, err := NewInitiator(config, sd, log)
			if err != nil {
				log.Errorln("could not start Initiator: ", err)
				return
			}
			i.initiators.Add(SpiToInt64(initiator.IkeSpiI), initiator)
			// TODO - currently this is break before make
			if err = RunSession(initiator); err == context.DeadlineExceeded {
				initiator.Logger.Info("ReKeying: ")
				continue
			} else if err == context.Canceled {
				break
			}
			time.Sleep(time.Second * 5)
		}
	}()
}

// ShutDown closes all active IKE sessions
func (i *IkeCmd) ShutDown(err error) {
	// shutdown sessions
	i.sessions.ForEach(func(session *Session) {
		// rely on this to drain replies
		session.Close(err)
	})
}

// Run loops until there is a socket error
func (i *IkeCmd) Run(config *Config, log *logrus.Logger) error {
	for {
		// this will return with error when there is a socket error
		msg, err := ReadMessage(i.conn, log)
		if err != nil {
			return err
		}
		i.processPacket(msg, config, log)
	}
}
