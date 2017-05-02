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

func waitForSignal(cancel context.CancelFunc, logger log.Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel()
	level.Warn(logger).Log("signal", sig.String())
}

var localPskID = &ike.PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

var localID = &ike.CertIdentity{}

var remotePskID = &ike.PskIdentities{
	Primary: "ak@msgbox.io",
	Ids:     map[string][]byte{"ak@msgbox.io": []byte("foo")},
}

var remoteID = &ike.CertIdentity{}

var isDebug bool

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

	flag.BoolVar(&isDebug, "debug", isDebug, "debug logs")

	flag.Parse()

	// crypto keys & names
	if caFile != "" {
		roots, err := ike.LoadRoot(caFile)
		if err != nil {
			panic(err)
		}
		remoteID.Roots = roots
	}
	if certFile != "" {
		certs, err := ike.LoadCerts(certFile)
		if err != nil {
			panic(err)
		}
		localID.Certificate = certs[0]
	}
	if keyFile != "" {
		key, err := ike.LoadKey(keyFile)
		if err != nil {
			panic(err)
		}
		localID.PrivateKey = key
	}
	if peerID != "" {
		remoteID.Name = peerID
	}

	config = ike.DefaultConfig()
	if !isTunnelMode {
		config.IsTransportMode = true
	}
	return
}

func main() {
	config, localString, remoteString := loadConfig()
	config.LocalID = localPskID
	config.RemoteID = remotePskID

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	if isDebug {
		logger = level.NewFilter(logger, level.AllowDebug())
		// crypto.DebugCrypto = true
	}
	logger = log.With(logger, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)

	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel, logger)

	ifs, _ := net.InterfaceAddrs()
	logger.Log("interfaces", spew.Sprintf("%#v", ifs))
	// this should load the xfrm modules
	// requires root
	cb := func(msg interface{}) {
		logger.Log("xfrm:", spew.Sprintf("%#v", msg))
	}
	platform.ListenForEvents(cxt, cb, logger)

	pconn, err := ike.Listen("udp", localString, logger)
	if err != nil {
		panic(fmt.Sprintf("Listen: %+v", err))
	}
	// requires root
	if err := platform.SetSocketBypas(pconn.Inner(), syscall.AF_INET6); err != nil {
		panic(fmt.Sprintf("Bypass: %+v", err))
	}

	cmd := ike.NewCmd(pconn, &ike.SessionCallback{
		AddSa: func(session *ike.Session, sa *platform.SaParams) error {
			platform.InstallPolicy(sa, logger)
			return platform.InstallChildSa(sa, logger)
		},
		RemoveSa: func(session *ike.Session, sa *platform.SaParams) error {
			platform.RemovePolicy(sa, logger)
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

	closing := false
	go func() {
		// wait for app shutdown
		<-cxt.Done()
		closing = true
		cmd.ShutDown(cxt.Err())
		pconn.Close()
		wg.Done()
	}()

	// this will return when there is a socket error
	err = cmd.Run(config, logger)
	if !closing {
		// ignore when caused by the close call above
		if isDebug {
			fmt.Printf("Error: %+v\n", err)
		} else {
			logger.Log("error", err)
		}
		cancel()
	}
	// wait for remaining sessions to shutdown
	wg.Wait()
	fmt.Printf("shutdown: %v\n", cxt.Err())
}
