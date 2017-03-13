package ike

import (
	"context"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/msgboxio/ike/platform"
	"github.com/pkg/errors"
)

// Cmd provides utilities for managing sessions
type Cmd struct {
	// map of initiator spi -> session
	sessions Sessions
	conn     Conn
	cb       SessionCallback
}

func NewCmd(conn Conn, cb SessionCallback) *Cmd {
	return &Cmd{
		sessions: NewSessions(),
		conn:     conn,
		cb:       cb,
	}
}

func (i *Cmd) AddSa(sa *platform.SaParams) error {
	return i.cb.AddSa(nil, sa)
}
func (i *Cmd) RemoveSa(sa *platform.SaParams) error {
	return i.cb.RemoveSa(nil, sa)
}

// dont call cb.onError
func (i *Cmd) onError(session *Session, err error) {
	if err == ErrorRekeyDeadlineExceeded {
		session.Close(context.DeadlineExceeded)
	} else {
		session.Close(context.Canceled)
	}
}

func (i *Cmd) runSession(spi uint64, s *Session) (err error) {
	i.sessions.Add(spi, s)
	err = RunSession(s)
	switch errors.Cause(err) {
	case errPeerRemovedIkeSa:
		s.HandleClose()
	default:
		s.Logger.Warnf("Error: %+v", err)
	}
	s.Logger.Infof("Remove IKE SA: %#x<=>%#x: %s", s.IkeSpiI, s.IkeSpiR, err)
	// wait for session to finish
	i.sessions.Remove(spi)
	return
}

// newResponder handles IKE_SA_INIT requests & replies
func (i *Cmd) newResponder(spi uint64, msg *Message, config *Config, log *logrus.Logger) (session *Session, err error) {
	// consider creating a new session
	// is it a IKE_SA_INIT req ?
	init, err := parseInit(msg)
	if err != nil {
		return nil, err
	}
	if err := CheckInitRequest(config, init, msg.RemoteAddr); err != nil {
		// handle errors that need reply: COOKIE or DH
		if reply := InitErrorNeedsReply(init, config, msg.RemoteAddr, err); reply != nil {
			data, err := EncodeMessage(reply, nil, false, log)
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

// RunInitiator starts & watches over on initiator session in a separate goroutine
func (i *Cmd) RunInitiator(remoteAddr net.Addr, config *Config, log *logrus.Logger) {
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
func (i *Cmd) ShutDown(err error) {
	// shutdown sessions
	i.sessions.ForEach(func(session *Session) {
		// rely on this to drain replies
		session.Close(err)
	})
}

// Run loops until there is a socket error
func (i *Cmd) Run(config *Config, log *logrus.Logger) error {
	for {
		// this will return with error when there is a socket error
		msg, err := ReadMessage(i.conn, log)
		if err != nil {
			return err
		}
		// convert for map lookup
		spi := SpiToInt64(msg.IkeHeader.SpiI)
		// check if a session exists
		session, found := i.sessions.Get(spi)
		if !found {
			var err error
			session, err = i.newResponder(spi, msg, config, log)
			if err != nil {
				log.Warning("drop packet: ", err)
				continue
			}
		}
		session.PostMessage(msg)
	}
}