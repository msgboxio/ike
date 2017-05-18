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

// Cmd provides utilities for building ike apps
type Cmd struct {
	sessions Sessions // map of initiator spi -> session
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

func (i *Cmd) runSession(spi uint64, sess *Session) (err error) {
	i.sessions.Add(spi, sess)
	// wait for session to finish
	err = RunSession(sess)
	switch errors.Cause(err) {
	case errPeerRemovedIkeSa:
		sess.Close(errPeerRemovedIkeSa)
	default:
		sess.Close(err)
		sess.Logger.Log("CLOSE", err)
	}
	i.sessions.Remove(spi)
	sess.Logger.Log("IKE_SA", "removed", "SESSION", fmt.Sprintf("%s<=>%s", sess.IkeSpiI, sess.IkeSpiR))
	return
}

// RunInitiator starts & watches over on initiator session in a separate goroutine
func (i *Cmd) RunInitiator(remoteAddr net.Addr, config *Config, log log.Logger) {
	go func() {
		for {
			initiator, err := NewInitiator(config, remoteAddr, i.conn, i.cb, log)
			if err != nil {
				log.Log("ERROR", err, "MSG", "could not start Initiator")
				return
			}
			spi := SpiToInt64(initiator.IkeSpiI)
			// if peer did not rekey in time
			if err = i.runSession(spi, initiator); err == errorRekeyDeadlineExceeded {
				initiator.Logger.Log("REKEY", "deadline exceeded")
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
	forUnknownSession := func(spi uint64, msg *Message) (sess *Session, err error) {
		// handle IKE_SA_INIT requests
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
			session, err = forUnknownSession(spi, msg)
			if err != nil {
				level.Warn(log).Log("DROP", err)
				continue
			}
		}
		session.PostMessage(msg)
	}
}
