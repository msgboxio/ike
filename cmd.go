package ike

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
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
	// wait for session to finish
	err = RunSession(s)
	switch errors.Cause(err) {
	case errPeerRemovedIkeSa:
		s.HandleClose()
	default:
		level.Warn(s.Logger).Log("err", err)
	}
	i.sessions.Remove(spi)
	s.Logger.Log("IKE_SA", "removed", "session", fmt.Sprintf("%s<=>%s", s.IkeSpiI, s.IkeSpiR))
	return
}

// newResponder handles IKE_SA_INIT requests & replies
func (i *Cmd) newResponder(spi uint64, msg *Message, config *Config, log log.Logger) (session *Session, err error) {
	// consider creating a new session
	if err = HandleInitRequest(msg, i.conn, config, log); err != nil {
		// dont create a new session
		return
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
func (i *Cmd) RunInitiator(remoteAddr net.Addr, config *Config, log log.Logger) {
	go func() {
		for { // restart conn
			sd := &SessionData{
				Conn:   i.conn,
				Remote: remoteAddr,
				Cb:     i.cb,
			}
			initiator, err := NewInitiator(config, sd, log)
			if err != nil {
				level.Error(log).Log("msg", "could not start Initiator", "err", err)
				return
			}
			spi := SpiToInt64(initiator.IkeSpiI)
			// TODO - currently this is break before make
			if err = i.runSession(spi, initiator); err == context.DeadlineExceeded {
				level.Info(initiator.Logger).Log("msg", "reKeying ")
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
func (i *Cmd) Run(config *Config, log log.Logger) error {
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
				level.Warn(log).Log("msg", "drop packet: ", "err", err)
				continue
			}
		}
		session.PostMessage(msg)
	}
}
