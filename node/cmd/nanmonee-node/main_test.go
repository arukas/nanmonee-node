package main

import (
	"context"
	"testing"
	"time"

	noderuntime "nanmonee/node/internal/runtime"
	"nanmonee/node/internal/worker"
)

type closingBackground struct {
	closed chan struct{}
}

func (b closingBackground) Observation() worker.Observation { return worker.Observation{} }
func (b closingBackground) Run(context.Context) error       { return nil }
func (b closingBackground) Close() error {
	close(b.closed)
	return nil
}

func TestCloseAllWaitsForFinalSamplingBeforeReleasingTheSpool(t *testing.T) {
	runtime, err := noderuntime.NewPanelOwned(noderuntime.ProtocolVless)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	engine := closingBackground{closed: make(chan struct{})}
	workerDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		closeAll(runtime, engine, workerDone)
		close(done)
	}()
	select {
	case <-engine.closed:
		t.Fatal("the spool lock was released while the worker was still sampling")
	case <-time.After(50 * time.Millisecond):
	}
	close(workerDone)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish after the worker stopped")
	}
	select {
	case <-engine.closed:
	default:
		t.Fatal("the spool was not closed after final sampling")
	}
}
