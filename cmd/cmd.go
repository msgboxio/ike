package cmd

import (
	cxt "context"

	"context"
	"net"

	"github.com/msgboxio/ike"
	"github.com/msgboxio/log"
)

// map of initiator spi -> session
var sessions = ike.NewSessions()

var intiators = ike.NewSessions()

// runs on main goroutine
func watchSession(spi uint64, session *ike.Session) {
	sessions.Add(spi, session)
	// wait for session to finish
	go func() {
		<-session.Done()
		sessions.Remove(spi)
		log.Infof("Removed IKE SA 0x%x", spi)
	}()
}

func newSession(msg *ike.Message, pconn ike.Conn, config *ike.Config) (*ike.Session, error) {
	// needed later
	spi := ike.SpiToInt64(msg.IkeHeader.SpiI)
	var err error
	// check if this is a response to our INIT request
	session, found := intiators.Get(spi)
	if found {
		// TODO - check if we already have a connection to this host
		// close the initiator session if we do
		// check if incoming message is an acceptable Init Response
		if err = ike.CheckInitResponseForSession(session, msg); err != nil {
			return session, err
		}
		// rewrite LocalAddr
		ike.ContextCallback(session).(*callback).local = msg.LocalAddr
		// remove from initiators map
		intiators.Remove(spi)
	} else {
		// is it a IKE_SA_INIT req ?
		if err = ike.CheckInitRequest(config, msg); err != nil {
			// handle errors that need reply: COOKIE or DH
			if reply := ike.InitErrorNeedsReply(msg, config, err); reply != nil {
				pconn.WritePacket(reply, msg.RemoteAddr)
			}
			return nil, err
		}
		// create and run session
		cxt := ike.WithCallback(context.Background(), ikeCallback(pconn, msg.LocalAddr, msg.RemoteAddr))
		session, err = ike.NewResponder(cxt, config, msg)
		if err != nil {
			return nil, err
		}
		go session.Run()
	}
	return session, nil
}

// runs on main goroutine
// loops until there is a socket error
func processPacket(pconn ike.Conn, msg *ike.Message, config *ike.Config) {
	// convert spi to uint64 for map lookup
	spi := ike.SpiToInt64(msg.IkeHeader.SpiI)
	// check if a session exists
	session, found := sessions.Get(spi)
	if !found {
		var err error
		session, err = newSession(msg, pconn, config)
		if err != nil {
			if ce, ok := err.(ike.CookieError); ok {
				// let retransmission take care to sending init with cookie
				// session is always returned for CookieError
				session.SetCookie(ce.Cookie)
			} else {
				log.Warningf("drop packet: %s", err)
			}
			return
		}
		// host based selectors can be added directly since both addresses are available
		if err := session.AddHostBasedSelectors(ike.AddrToIp(msg.LocalAddr), ike.AddrToIp(msg.RemoteAddr)); err != nil {
			log.Warningf("could not add selectors: %s", err)
		}
		watchSession(spi, session)
	}
	session.PostMessage(msg)
}

func RunInitiator(remoteAddr net.Addr, pconn ike.Conn, config *ike.Config) {
	go func() {
		for { // restart conn
			withCb := ike.WithCallback(context.Background(), ikeCallback(pconn, nil, remoteAddr))
			initiator := ike.NewInitiator(withCb, config)
			intiators.Add(ike.SpiToInt64(initiator.IkeSpiI), initiator)
			go initiator.Run()
			// wait for initiator to finish
			<-initiator.Done()
			if initiator.Err() == cxt.DeadlineExceeded {
				break
			}
		}
	}()
}

func ShutDown(err error) {
	// shutdown sessions
	sessions.ForEach(func(session *ike.Session) {
		// rely on this to drain replies
		session.Close(err)
		// wait until client is done
		<-session.Done()
	})
}

func Run(pconn ike.Conn, config *ike.Config) error {
	for {
		// this will return with error when there is a socket error
		msg, err := ike.ReadMessage(pconn)
		if err != nil {
			return err
		}
		processPacket(pconn, msg, config)
	}
}
