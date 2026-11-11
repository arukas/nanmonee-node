package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nanmonee/node/internal/config"
	"nanmonee/node/internal/control"
	"nanmonee/node/internal/panel"
	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/traffic"
	"nanmonee/node/internal/worker"
)

// shutdownGrace bounds graceful termination so a stuck connection cannot block
// the restart that operators are usually trying to perform.
const shutdownGrace = 10 * time.Second

func main() {
	configPath := flag.String("config", "", "path to the owner-only startup config")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("the -config option is required")
	}
	startup, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if startup.PanelOwned {
		runPanelOwned(startup)
		return
	}
	runSelfManaged(startup)
}

// runSelfManaged is the T35 behaviour: the control plane applies snapshots and
// the process owns its inbound configuration from the startup file.
func runSelfManaged(startup config.Config) {
	runtime, err := noderuntime.New(startup.Inbound)
	if err != nil {
		log.Fatal(err)
	}
	serve(startup, runtime, nil)
}

// runPanelOwned starts without a kernel. The proxy stays closed until the first
// successful panel snapshot, and external applies are refused from then on.
func runPanelOwned(startup config.Config) {
	client, err := panel.NewClient(startup.Panel)
	if err != nil {
		log.Fatal(err)
	}
	protocol, err := config.ProtocolForNodeType(startup.Panel.NodeType)
	if err != nil {
		log.Fatal(err)
	}
	runtime, err := noderuntime.NewPanelOwned(protocol)
	if err != nil {
		log.Fatal(err)
	}
	spool, err := traffic.Open(startup.DataDir, client.Identity(), runtime.Status().RuntimeID)
	if err != nil {
		_ = runtime.Close()
		log.Fatal(err)
	}
	engine, err := worker.New(worker.Options{Client: client, Runtime: runtime, Spool: spool})
	if err != nil {
		_ = spool.Close()
		_ = runtime.Close()
		log.Fatal(err)
	}
	serve(startup, runtime, panelRunner{engine: engine, spool: spool})
}

// panelRunner couples the worker lifetime to the process lifetime.
type panelRunner struct {
	engine *worker.Worker
	spool  *traffic.Spool
}

func (r panelRunner) Observation() worker.Observation { return r.engine.Observation() }

func (r panelRunner) Run(ctx context.Context) error { return r.engine.Run(ctx) }

func (r panelRunner) Close() error { return r.spool.Close() }

// background is the optional panel worker attached to the control plane.
type background interface {
	worker.Observer
	Run(context.Context) error
	Close() error
}

func serve(startup config.Config, runtime *noderuntime.Runtime, engine background) {
	var observer worker.Observer
	if engine != nil {
		observer = engine
	}
	listener, err := net.Listen("tcp", startup.Control.Listen)
	if err != nil {
		_ = runtime.Close()
		log.Fatal(err)
	}
	server := control.NewServer(runtime, startup.Control.Secret, observer)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()

	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	workerErrors := make(chan error, 1)
	workerDone := make(chan struct{})
	if engine != nil {
		go func() {
			defer close(workerDone)
			err := engine.Run(workerCtx)
			if err != nil {
				log.Printf("panel worker stopped: %v", err)
			}
			workerErrors <- err
		}()
		log.Printf("panel-owned %s mode: authorizations come from the panel only", runtime.Status().Protocol)
	}
	log.Printf("nanmonee-node control listening on %s", startup.Control.Listen)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serveErrors:
		stopWorker()
		closeAll(runtime, engine, workerDone)
		if err != nil {
			log.Fatal(err)
		}
		return
	case <-workerErrors:
		// The worker must not die silently; a dead reporter is an outage.
		signals = nil
		stopWorker()
		closeAll(runtime, engine, workerDone)
		log.Fatal("panel worker stopped; refusing to serve without metering")
	case <-signals:
	}

	stopWorker()
	timer := time.AfterFunc(shutdownGrace, server.Stop)
	server.GracefulStop()
	timer.Stop()
	closeAll(runtime, engine, workerDone)
}

func closeAll(runtime *noderuntime.Runtime, engine background, workerDone <-chan struct{}) {
	if engine != nil {
		// Keep the single-writer lock until final sampling and reporting finish.
		<-workerDone
		if err := engine.Close(); err != nil {
			log.Printf("close traffic spool: %v", err)
		}
	}
	if err := runtime.Close(); err != nil {
		log.Printf("close runtime: %v", err)
	}
}
