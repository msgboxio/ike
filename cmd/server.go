package main

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"

	"github.com/msgboxio/context"
	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/msgboxio/log"
)

func waitForSignal(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel(errors.New("received signal: " + sig.String()))
}

func loadConfig() (*ike.Config, string, string, *x509.CertPool, []*x509.Certificate, *rsa.PrivateKey) {
	var localString, remoteString string
	flag.StringVar(&localString, "local", "0.0.0.0:5000", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	var caFile, certFile, keyFile string
	flag.StringVar(&caFile, "ca", "", "PEM encoded ca certificate")
	flag.StringVar(&certFile, "cert", "", "PEM encoded peer certificate")
	flag.StringVar(&keyFile, "key", "", "PEM encoded peer key")

	flag.Set("logtostderr", "true")
	flag.Parse()

	config := ike.DefaultConfig()
	if !isTunnelMode {
		config.IsTransportMode = true
	}
	roots, err := ike.LoadRoot(caFile)
	if err != nil {
		log.Fatal(err)
	}
	certs, err := ike.LoadCerts(certFile)
	if err != nil {
		log.Warningf("Cert: %s", err)
	}
	key, err := ike.LoadKey(keyFile)
	if err != nil {
		log.Warningf("Key: %s", err)
	}

	return config, localString, remoteString, roots, certs, key
}

func packetWriter(pconn *ipv4.PacketConn, to net.Addr) ike.WriteData {
	return func(reply []byte) error {
		return ike.WritePacket(pconn, reply, to)
	}
}
func saInstaller(local, remote net.IP) ike.SaCallback {
	return func(sa *platform.SaParams) error {
		if sa.IsResponder {
			sa.Ini = remote
			sa.Res = local
		} else {
			sa.Ini = local
			sa.Res = remote
		}
		log.Infof("Installing Child SA: %#x<=>%#x; [%s]%s<=>%s[%s]",
			sa.SpiI, sa.SpiR, sa.Ini, sa.IniNet, sa.ResNet, sa.Res)
		err := platform.InstallChildSa(sa)
		log.Info("Installed Child SA; error:", err)
		return err
	}
}
func saRemover(local, remote net.IP) ike.SaCallback {
	return func(sa *platform.SaParams) error {
		if sa.IsResponder {
			sa.Ini = remote
			sa.Res = local
		} else {
			sa.Ini = local
			sa.Res = remote
		}
		err := platform.RemoveChildSa(sa)
		log.Info("Removed child SA")
		return err
	}
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
		log.Infof("Removed SA 0x%x", spi)
	}()
}

// runs on main goroutine
// loops until there is a socket error
func processPackets(pconn *ipv4.PacketConn, config *ike.Config) {
	var local, remote net.IP
	var onAddSa, onRemoveSa ike.SaCallback
	for {
		msg, err := ike.ReadMessage(pconn)
		if err != nil {
			log.Error(err)
			break
		}
		// convert spi to uint64 for map lookup
		spi := ike.SpiToInt(msg.IkeHeader.SpiI)
		// check if a session exists
		session, found := sessions[spi]
		if !found {
			// needed later
			local = ike.AddrToIp(msg.LocalAddr)
			remote = ike.AddrToIp(msg.RemoteAddr)
			onAddSa = saInstaller(local, remote)
			onRemoveSa = saRemover(local, remote)
			// check if we caused this
			session, found = intiators[spi]
			if found {
				// TODO - check if we already have a connection to this host
				// close the initiator session if we do
				// check if incoming message is an acceptable Init Response
				if err := ike.CheckInitResponseForSession(session, msg); err != nil {
					log.Warning("drop packet")
					continue
				}
				ike.SetInitiatorParameters(session, msg)
				session.AddSaHandlers(onAddSa, onRemoveSa)
				session.AddHostBasedSelectors(local, remote)
				// remove from initiators map and place into normal map
				delete(intiators, spi)
				watchSession(spi, session)
			}
		}
		if !found {
			// create and run session
			session, err = ike.NewResponder(context.Background(), localId, remoteId, config, msg)
			if err != nil {
				log.Error(err)
				if err == protocol.ERR_INVALID_KE_PAYLOAD {
					tr := config.ProposalIke[protocol.TRANSFORM_TYPE_DH].Transform.TransformId
					ike.WritePacket(pconn, ike.InvalidKeMsg(msg.IkeHeader.SpiI, tr), msg.RemoteAddr)
				}
				continue
			}
			// host based selectors can be added directly since both addresses are available
			session.AddHostBasedSelectors(local, remote)
			session.AddSaHandlers(onAddSa, onRemoveSa)
			go session.Run(packetWriter(pconn, msg.RemoteAddr))
			watchSession(spi, session)
		}
		session.PostMessage(msg)
	}
}

func main() {
	config, localString, remoteString, roots, cert, key := loadConfig()
	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel)

	if cert != nil {
		localId.Certificate = cert[0]
	}
	localId.PrivateKey = key
	remoteId.Roots = roots

	ifs, _ := net.InterfaceAddrs()
	log.Infof("Available interfaces %+v", ifs)
	// this should load the xfrm modules
	// requires root
	if xfrm := platform.ListenForEvents(cxt); xfrm != nil {
		go func() {
			<-xfrm.Done()
			if err := xfrm.Err(); err != context.Canceled {
				log.Error(err)
			}
			xfrm.Close()
		}()
	}

	pconn, err := ike.Listen(localString)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("socket listening: %s", pconn.Conn.LocalAddr())

	// requires root
	if err := platform.SetSocketBypas(pconn.Conn, syscall.AF_INET); err != nil {
		log.Error(err)
	}

	if remoteString != "" {
		remoteAddr, _ := net.ResolveUDPAddr("udp", remoteString)
		// resolution gives us v4 mapped addressees for ip4
		remoteAddr = &net.UDPAddr{
			IP:   remoteAddr.IP.To4(),
			Port: remoteAddr.Port,
		}
		initiator := ike.NewInitiator(context.Background(), localId, remoteId, remoteAddr, pconn.Conn.LocalAddr(), config)
		intiators[ike.SpiToInt(initiator.IkeSpiI)] = initiator
		go initiator.Run(packetWriter(pconn, remoteAddr))
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

	// this will return when there is a socket error
	// usually caused by the close call above
	processPackets(pconn, config)
	cancel(context.Canceled)

	wg.Wait()
	fmt.Printf("shutdown: %v\n", cxt.Err())
}
