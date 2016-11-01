package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/davecgh/go-spew/spew"
	"github.com/msgboxio/context"
	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/log"
)

func waitForSignal(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel(errors.New("received signal: " + sig.String()))
}

// var localId = &ike.PskIdentities{
// Primary: "ak@msgbox.io",
// Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
// }
var localId = &ike.CertIdentity{}

// var remoteId = &ike.PskIdentities{
// Primary: "bk@msgbox.io",
// Ids:     map[string][]byte{"bk@msgbox.io": []byte("foo")},
// }
var remoteId = &ike.CertIdentity{}

func loadConfig() (config *ike.Config, localString string, remoteString string) {
	flag.StringVar(&localString, "local", "0.0.0.0:4500", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	var caFile, certFile, keyFile, peerID string
	flag.StringVar(&caFile, "ca", "", "PEM encoded ca certificate")
	flag.StringVar(&certFile, "cert", "", "PEM encoded peer certificate")
	flag.StringVar(&keyFile, "key", "", "PEM encoded peer key")
	flag.StringVar(&peerID, "peer", "", "Peer ID")

	flag.Set("logtostderr", "true")
	flag.Parse()

	config = ike.DefaultConfig()
	if !isTunnelMode {
		config.IsTransportMode = true
	}
	// crypto keys & names
	if caFile != "" {
		roots, err := ike.LoadRoot(caFile)
		if err != nil {
			log.Fatal(err)
		}
		remoteId.Roots = roots
	}
	if certFile != "" {
		certs, err := ike.LoadCerts(certFile)
		if err != nil {
			log.Warningf("Cert: %s", err)
		}
		localId.Certificate = certs[0]
	}
	if keyFile != "" {
		key, err := ike.LoadKey(keyFile)
		if err != nil {
			log.Warningf("Key: %s", err)
		}
		localId.PrivateKey = key
	}
	remoteId.Name = peerID
	return
}

// map of initiator spi -> session
var sessions = make(map[uint64]*ike.Session)

var intiators = make(map[uint64]*ike.Session)

// runs on main goroutine
// sesions map has data race
// delete operation runs in a seperate goroutime - worth fixing ?
func watchSession(spi uint64, session *ike.Session) {
	sessions[spi] = session
	// wait for session to finish
	go func() {
		<-session.Done()
		delete(sessions, spi)
		log.Infof("Removed IKE SA 0x%x", spi)
	}()
}

func newSession(msg *ike.Message, pconn ike.Conn, config *ike.Config) (*ike.Session, error) {
	// needed later
	spi := ike.SpiToInt64(msg.IkeHeader.SpiI)
	var err error
	// check if this is a response to our INIT request
	session, found := intiators[spi]
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
		delete(intiators, spi)
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
		session, err = ike.NewResponder(cxt, localId, remoteId, config, msg)
		if err != nil {
			return nil, err
		}
		go session.Run()
	}
	return session, nil
}

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

// runs on main goroutine
// loops until there is a socket error
func processPacket(pconn ike.Conn, msg *ike.Message, config *ike.Config) {
	// convert spi to uint64 for map lookup
	spi := ike.SpiToInt64(msg.IkeHeader.SpiI)
	// check if a session exists
	session, found := sessions[spi]
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

func main() {
	config, localString, remoteString := loadConfig()
	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel)

	ifs, _ := net.InterfaceAddrs()
	log.Infof("Available interfaces %+v", ifs)
	// this should load the xfrm modules
	// requires root
	cb := func(msg interface{}) {
		log.V(3).Infof("xfrm: \n%s", spew.Sdump(msg))
	}
	if xfrm := platform.ListenForEvents(cxt, cb); xfrm != nil {
		go func() {
			<-xfrm.Done()
			if err := xfrm.Err(); err != context.Canceled {
				log.Error(err)
			}
			xfrm.Close()
		}()
	}

	pconn, err := ike.Listen("udp", localString)
	if err != nil {
		log.Fatal(err)
	}

	// requires root
	if err := platform.SetSocketBypas(ike.InnerConn(pconn), syscall.AF_INET6); err != nil {
		log.Error(err)
	}

	if remoteString != "" {
		remoteAddr, err := net.ResolveUDPAddr("udp", remoteString)
		if err != nil {
			log.Fatalf("error resolving: %+v", err)
		}
		cxt := ike.WithCallback(context.Background(), ikeCallback(pconn, nil, remoteAddr))
		initiator := ike.NewInitiator(cxt, localId, remoteId, config)
		intiators[ike.SpiToInt64(initiator.IkeSpiI)] = initiator
		go initiator.Run()
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		// wait for app shutdown
		<-cxt.Done()
		// shutdown sessions
		for _, session := range sessions {
			// rely on this to drain replies
			session.Close(cxt.Err())
			// wait until client is done
			<-session.Done()
		}
		pconn.Close()
		wg.Done()
	}()

	for {
		// this will return when there is a socket error
		// usually caused by the close call above
		msg, err := ike.ReadMessage(pconn)
		if err != nil {
			log.Error(err)
			break
		}
		processPacket(pconn, msg, config)
	}
	cancel(context.Canceled)

	wg.Wait()
	fmt.Printf("shutdown: %v\n", cxt.Err())
}
