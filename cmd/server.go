package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/platform"
)

var logger log.Logger

func waitForSignal(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel()
	level.Error(logger).Log(sig.String())
}

var localID = &ike.PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

// var localID = &ike.CertIdentity{}

var remoteID = &ike.PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

// var remoteID = &ike.CertIdentity{}

func loadConfig() (config *ike.Config, localString string, remoteString string) {
	flag.StringVar(&localString, "local", "0.0.0.0:4500", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var isTunnelMode bool
	flag.BoolVar(&isTunnelMode, "tunnel", false, "use tunnel mode?")

	var caFile, certFile, keyFile, peerID string
	flag.StringVar(&caFile, "ca", "", "PEM encoded ca certificate")
	flag.StringVar(&certFile, "cert", "", "PEM encoded peer certificate")
	flag.StringVar(&keyFile, "key", "", "PEM encoded peer key")
	flag.StringVar(&peerID, "peerid", "", "Peer ID")

	var isDebug bool
	flag.BoolVar(&isDebug, "debug", isDebug, "debug logs")

	flag.Parse()

	/*
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
				level.Warn(log).Log("Cert: %s", err)
			}
			localId.Certificate = certs[0]
		}
		if keyFile != "" {
			key, err := ike.LoadKey(keyFile)
			if err != nil {
				level.Warn(log).Log("Key: %s", err)
			}
			localId.PrivateKey = key
		}
		if peerID != "" {
			remoteId.Name = peerID
		}
	*/

	config = ike.DefaultConfig()
	if !isTunnelMode {
		config.IsTransportMode = true
	}
	config.LocalID = localID
	config.RemoteID = remoteID

	logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	if isDebug {
		logger = level.NewFilter(logger, level.AllowDebug())
	}
	return
}

func main() {
	config, localString, remoteString := loadConfig()
	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel)

	ifs, _ := net.InterfaceAddrs()
	logger.Log("Available interfaces", ifs)
	// this should load the xfrm modules
	// requires root
	cb := func(msg interface{}) {
		logger.Log("xfrm:", spew.Sdump(msg))
	}
	platform.ListenForEvents(cxt, cb, logger)

	pconn, err := ike.Listen("udp", localString)
	if err != nil {
		panic(err)
	}
	// requires root
	if err := platform.SetSocketBypas(ike.InnerConn(pconn), syscall.AF_INET6); err != nil {
		panic(err)
	}

	cmd := ike.NewCmd(pconn, ike.SessionCallback{
		AddSa: func(session *ike.Session, sa *platform.SaParams) error {
			return platform.InstallChildSa(sa, logger)
		},
		RemoveSa: func(session *ike.Session, sa *platform.SaParams) error {
			return platform.RemoveChildSa(sa, logger)
		},
	})

	if remoteString != "" {
		remoteAddr, err := net.ResolveUDPAddr("udp", remoteString)
		if err != nil {
			panic(err)
		}
		cmd.RunInitiator(remoteAddr, config, logger)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		// wait for app shutdown
		<-cxt.Done()
		cmd.ShutDown(cxt.Err())
		pconn.Close()
		wg.Done()
	}()

	err = cmd.Run(config, logger)
	// this will return when there is a socket error
	// usually caused by the close call above
	logger.Log("error", err)
	cancel()
	// wait for remaining sessions to shutdown
	wg.Wait()
	fmt.Printf("shutdown: %v\n", cxt.Err())
}
