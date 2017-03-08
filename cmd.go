package ike

import (
	"context"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
	"github.com/pkg/errors"
)

// IkeCmd provides utilities that help in managing sessions
type IkeCmd struct {
	// map of initiator spi -> session
	sessions Sessions
	conn     Conn
	cb       SessionCallback
}

func NewCmd(conn Conn, cb SessionCallback) *IkeCmd {
	return &IkeCmd{
		sessions: NewSessions(),
		conn:     conn,
		cb:       cb,
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
	if err == ErrorRekeyDeadlineExceeded {
		session.Close(context.DeadlineExceeded)
	} else {
		session.Close(context.Canceled)
	}
}

func (i *IkeCmd) runSession(spi uint64, s *Session) (err error) {
	i.sessions.Add(spi, s)
	err = RunSession(s)
	// wait for session to finish
	i.sessions.Remove(spi)
	s.Logger.Infof("Removed IKE SA: %+v", err)
	return
}

// newResponder handles IKE_SA_INIT requests & replies
func (i *IkeCmd) newResponder(spi uint64, msg *Message, config *Config, log *logrus.Logger) (session *Session, err error) {
	// consider creating a new session
	// is it a IKE_SA_INIT req ?
	if err := CheckInitRequest(config, msg); err != nil {
		// handle errors that need reply: COOKIE or DH
		if reply := InitErrorNeedsReply(msg, config, err); reply != nil {
			data, err := reply.Encode(nil, false, log)
			if err != nil {
				return nil, errors.Wrap(err, "error encoding init reply")
			}
			i.conn.WritePacket(data, msg.RemoteAddr)
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
	session, err = NewResponder(config, sd, msg, log)
	if err != nil {
		return nil, err
	}
	go i.runSession(spi, session)
	return
}

// runs on main goroutine
func (i *IkeCmd) processPacket(msg *Message, config *Config, log *logrus.Logger) {
	// convert for map lookup
	spi := SpiToInt64(msg.IkeHeader.SpiI)
	// check if a session exists
	session, found := i.sessions.Get(spi)
	if !found {
		var err error
		session, err = i.newResponder(spi, msg, config, log)
		if err != nil {
			log.Warning("drop packet: ", err)
			return
		}
	}
	session.PostMessage(msg)
}

// RunInitiator starts & watches over on initiator session in a separate goroutine
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
			spi := SpiToInt64(initiator.IkeSpiI)
			// TODO - currently this is break before make
			if err = i.runSession(spi, initiator); err == context.DeadlineExceeded {
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
