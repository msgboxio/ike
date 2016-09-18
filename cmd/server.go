package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

func decode(b []byte) (msg *ike.Message, err error) {
	msg = &ike.Message{}
	if err = msg.DecodeHeader(b); err != nil {
		return
	}
	if len(b) < int(msg.IkeHeader.MsgLength) {
		err = io.ErrShortBuffer
		return
	}
	// further decode
	if err = msg.DecodePayloads(b[protocol.IKE_HEADER_LEN:msg.IkeHeader.MsgLength], msg.IkeHeader.NextPayload); err != nil {
		// o.Notify(ERR_INVALID_SYNTAX)
		return
	}
	// decrypt later
	msg.Data = b
	return
}

// map of initiator spi -> session
var sessions = make(map[uint64]*ike.Session)

func runSession(spi uint64, session *ike.Session, pconn *ipv4.PacketConn, to net.Addr) {
	sessions[spi] = session
	for {
		select {
		case reply, ok := <-session.Replies():
			if !ok {
				break
			}
			if err := ike.WritePacket(pconn, reply, to); err != nil {
				session.Close(err)
				break
			}
		case <-session.Done():
			delete(sessions, spi)
			log.Infof("Finished SA 0x%x", spi)
			return
		}
	}
}

var localId = ike.PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}
var remoteId = ike.PskIdentities{
	Primary: "bk@msgbox.io",
	Ids:     map[string][]byte{"bk@msgbox.io": []byte("foo")},
}

func processPackets(pconn *ipv4.PacketConn, config *ike.Config) {
	var buf []byte
	for {
		b, remoteAddr, localIP, err := ike.ReadPacket(pconn)
		if err != nil {
			log.Error(err)
			break
		}
		if buf != nil {
			b = append(buf, b...)
			buf = nil
		}
		msg, err := decode(b)
		if err == io.ErrShortBuffer {
			buf = b
			continue
		}
		if err != nil {
			log.Error(err)
			continue
		}
		msg.LocalIp = localIP
		msg.RemoteIp = ike.AddrToIp(remoteAddr)
		// convert spi to uint64 for map lookup
		spi := ike.SpiToInt(msg.IkeHeader.SpiI)
		// check if a session exists
		session, found := sessions[spi]
		if !found {
			// create and run session
			session, err = ike.NewResponder(context.Background(), localId, remoteId, config, msg)
			if err != nil {
				log.Error(err)
				continue
			}
			go runSession(spi, session, pconn, remoteAddr)
		}
		session.HandleMessage(msg)
	}
}

func loadRoot(caCert string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	rootPEM, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	if ok := roots.AppendCertsFromPEM([]byte(rootPEM)); !ok {
		return nil, errors.New("failed to parse root certificate")
	}
	return roots, nil
}

func loadConfig() (*ike.Config, string, string) {
	var localString, remoteString string
	flag.StringVar(&localString, "local", "0.0.0.0:5000", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	var caCert string
	flag.StringVar(&caCert, "ca", "", "PEM encoded ca certificate")

	flag.Set("logtostderr", "true")
	flag.Parse()

	config := ike.DefaultConfig()
	if !isTunnelMode {
		config.IsTransportMode = true
	}
	if caCert == "" {
		if roots, err := x509.SystemCertPool(); err != nil {
			log.Fatal(err)
		} else {
			config.Roots = roots
		}
	} else if roots, err := loadRoot(caCert); err != nil {
		log.Fatal(err)
	} else {
		config.Roots = roots
	}
	return config, localString, remoteString
}

func main() {
	config, localString, remoteString := loadConfig()
	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel)

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
		remoteAddr, _ := net.ResolveUDPAddr("udp4", remoteString)
		initiator := ike.NewInitiator(context.Background(), localId, remoteId, ike.AddrToIp(remoteAddr).To4(), config)
		go runSession(ike.SpiToInt(initiator.IkeSpiI), initiator, pconn, remoteAddr)
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
