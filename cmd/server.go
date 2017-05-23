package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike"
	"github.com/msgboxio/ike/crypto"
	"github.com/msgboxio/ike/platform"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

func waitForSignal(cancel context.CancelFunc, logger log.Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	sig := <-c
	// sig is a ^C, handle it
	cancel()
	level.Warn(logger).Log("SIGNAL", sig.String())
}

var isDebug bool

func loadConfig() (config *ike.Config, localString string, remoteString string, err error) {
	flag.StringVar(&localString, "local", "0.0.0.0:4500", "address to bind to")
	flag.StringVar(&remoteString, "remote", "", "address to connect to")

	var localTunnel, remoteTunnel string
	flag.StringVar(&localTunnel, "localnet", "", "local network")
	flag.StringVar(&remoteTunnel, "remotenet", "", "remote network")

	var caFile, certFile, keyFile, peerID, peerPass, id, pass string
	flag.StringVar(&caFile, "ca", "", "PEM encoded ca certificate")
	flag.StringVar(&certFile, "cert", "", "PEM encoded peer certificate")
	flag.StringVar(&keyFile, "key", "", "PEM encoded peer key")
	flag.StringVar(&peerID, "peerid", "", "Peer ID")
	flag.StringVar(&peerPass, "peerpass", "", "Peer Password")
	flag.StringVar(&id, "id", "", "our ID")
	flag.StringVar(&pass, "pass", "", "our Password")

	var useESN bool
	flag.BoolVar(&useESN, "esn", useESN, "use ESN")

	keysOf := func(m map[string]protocol.TransformMap) (ret []string) {
		for k := range m {
			ret = append(ret, k)
		}
		return
	}
	var espSuite, ikeSuite string
	flag.StringVar(&espSuite, "esp", "aes128-sha256", spew.Sprintf("esp crypto: %v", keysOf(crypto.EspSuites)))
	flag.StringVar(&ikeSuite, "ike", "aes128-sha256-modp3072", spew.Sprintf("ike crypto: %v", keysOf(crypto.IkeSuites)))

	flag.BoolVar(&isDebug, "debug", isDebug, "debug logs")
	flag.Parse()

	config = ike.DefaultConfig()

	ok := false
	if config.ProposalEsp, ok = crypto.EspSuites[espSuite]; !ok {
		err = fmt.Errorf("esp suit %s is not available", espSuite)
		return
	}
	if config.ProposalIke, ok = crypto.IkeSuites[ikeSuite]; !ok {
		err = fmt.Errorf("ike suit %s is not available", ikeSuite)
		return
	}
	// ca & id for verifying peer
	if caFile != "" && peerID != "" {
		roots, _err := ike.LoadRoot(caFile)
		err = errors.Wrapf(_err, "loading %s", caFile)
		if err != nil {
			return
		}
		config.PeerID = &ike.CertIdentity{
			Roots:                roots,
			Name:                 peerID,
			AuthenticationMethod: protocol.AUTH_DIGITAL_SIGNATURE,
		}
	}
	if config.PeerID == nil {
		if peerID == "" && peerPass == "" {
			err = errors.New("peer credentials are missing")
			return
		}
		config.PeerID = &ike.PskIdentities{
			Primary: peerID,
			Ids:     map[string][]byte{peerID: []byte(peerPass)},
		}
	}
	// our key & certificate
	if certFile != "" && keyFile != "" {
		certs, _err := ike.LoadCerts(certFile)
		err = errors.Wrapf(_err, "loading %s", certFile)
		if err != nil {
			return
		}

		key, _err := ike.LoadKey(keyFile)
		err = errors.Wrapf(_err, "loading %s", keyFile)
		if err != nil {
			return
		}
		config.LocalID = &ike.CertIdentity{
			Certificate:          certs[0],
			PrivateKey:           key,
			AuthenticationMethod: protocol.AUTH_DIGITAL_SIGNATURE,
		}
	}
	if config.LocalID == nil {
		if id == "" && pass == "" {
			err = errors.New("our credentials are missing")
			return
		}
		config.LocalID = &ike.PskIdentities{
			Primary: id,
			Ids:     map[string][]byte{id: []byte(pass)},
		}
	}

	if localTunnel == "" && remoteTunnel == "" {
		config.IsTransportMode = true
	} else {
		_, localnet, _err := net.ParseCIDR(localTunnel)
		err = _err
		if err != nil {
			return
		}
		_, remotenet, _err := net.ParseCIDR(remoteTunnel)
		err = _err
		if err != nil {
			return
		}
		isInitiator := true
		if remoteString == "" {
			isInitiator = false
		}
		err = config.AddNetworkSelectors(localnet, remotenet, isInitiator)
	}
	if useESN {
		config.ProposalEsp.GetType(protocol.TRANSFORM_TYPE_ESN).TransformId = uint16(protocol.ESN)
	}
	return
}

func main() {
	config, localString, remoteString, err := loadConfig()
	if err != nil {
		fmt.Printf("Argument Error: %+v\n", err)
		panic(err)
	}

	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	if isDebug {
		logger = level.NewFilter(logger, level.AllowDebug())
		// crypto.DebugCrypto = true
	}
	logger = log.With(logger, "ts", log.DefaultTimestamp, "caller", log.DefaultCaller)

	cxt, cancel := context.WithCancel(context.Background())
	go waitForSignal(cancel, logger)

	ifs, _ := net.InterfaceAddrs()
	logger.Log("INTERFACES", fmt.Sprintf("%v", ifs))
	// this should load the xfrm modules
	// requires root
	cb := func(msg interface{}) {
		logger.Log("EVENT", spew.Sprintf("%#v", msg))
	}
	platform.ListenForEvents(cxt, cb, logger)

	pconn, err := ike.Listen("udp", localString, logger)
	if err != nil {
		panic(fmt.Sprintf("Listen: %+v", err))
	}
	// requires root
	if err := platform.SetSocketBypas(pconn.Inner()); err != nil {
		panic(fmt.Sprintf("Bypass: %+v", err))
	}

	cmd := ike.NewCmd(pconn, &ike.SessionCallback{
		InstallPolicy: func(session *ike.Session, pol *protocol.PolicyParams) error {
			return platform.InstallPolicy(session.SessionID, pol, logger, session.IsInitiator())
		},
		RemovePolicy: func(session *ike.Session, pol *protocol.PolicyParams) error {
			return platform.RemovePolicy(session.SessionID, pol, logger, session.IsInitiator())
		},
		InstallChildSa: func(session *ike.Session, sa *platform.SaParams) error {
			return platform.InstallChildSa(session.SessionID, sa, logger)
		},
		RemoveChildSa: func(session *ike.Session, sa *platform.SaParams) error {
			return platform.RemoveChildSa(session.SessionID, sa, logger)
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
		// this will cause cmd.Run to return
		pconn.Close()
		wg.Done()
	}()

	// this will return when there is a socket error
	err = cmd.Run(config, logger)
	if !closing {
		// ignore when caused by the close call above
		logger.Log("ERROR", err)
		if isDebug {
			fmt.Printf("STACK: %+v\n", err)
		}
		cancel()
	}
	// wait for remaining sessions to shutdown
	wg.Wait()
	fmt.Printf("SHUTDOWN: %v\n", cxt.Err())
}
