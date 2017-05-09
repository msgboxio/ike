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

// Cmd provides utilities for building simple command line apps
type Cmd struct {
	// map of initiator spi -> session
	sessions Sessions
	conn     Conn
	cb       *SessionCallback
}

func NewCmd(conn Conn, cb *SessionCallback) *Cmd {
	return &Cmd{
		sessions: NewSessions(),
		conn:     conn,
		cb:       cb,
	}
}

func (i *Cmd) onError(sess *Session, err error) {
	if err == ErrorRekeyDeadlineExceeded {
		sess.Close(context.DeadlineExceeded)
	} else {
		sess.Close(context.Canceled)
	}
}

func (i *Cmd) runSession(spi uint64, sess *Session) (err error) {
	i.sessions.Add(spi, sess)
	// wait for session to finish
	err = RunSession(sess)
	switch errors.Cause(err) {
	case errPeerRemovedIkeSa:
		sess.HandleClose()
	default:
		level.Warn(sess.Logger).Log("err", err)
	}
	i.sessions.Remove(spi)
	sess.Logger.Log("IKE_SA", "removed", "session", fmt.Sprintf("%s<=>%s", sess.IkeSpiI, sess.IkeSpiR))
	return
}

// onInitRequest handles IKE_SA_INIT requests & replies
func (i *Cmd) onInitRequest(spi uint64, msg *Message, config *Config, log log.Logger) (sess *Session, err error) {
	if err = checkInitRequest(msg, i.conn, config, log); err != nil {
		return nil, err
	}
	sess, err = NewResponder(config, i.conn, i.cb, msg, log)
	if err != nil {
		return nil, err
	}
	go i.runSession(spi, sess)
	return
}

// RunInitiator starts & watches over on initiator session in a separate goroutine
func (i *Cmd) RunInitiator(remoteAddr net.Addr, config *Config, log log.Logger) {
	go func() {
		for { // restart conn
			initiator, err := NewInitiator(config, remoteAddr, i.conn, i.cb, log)
			if err != nil {
				level.Error(log).Log("msg", "could not start Initiator", "err", err)
				return
			}
			spi := SpiToInt64(initiator.IkeSpiI)
			// TODO - currently this is break before make
			if err = i.runSession(spi, initiator); err == context.DeadlineExceeded {
				initiator.Logger.Log("msg", "reKeying")
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
	i.sessions.ForEach(func(sess *Session) {
		// rely on this to drain replies
		sess.Close(err)
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
			session, err = i.onInitRequest(spi, msg, config, log)
			if err != nil {
				level.Warn(log).Log("DROP", err)
				continue
			}
		}
		session.PostMessage(msg)
	}
}
