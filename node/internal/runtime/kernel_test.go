package runtime

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestSingBoxKernelStartsEmptyAndHotUpdatesWithoutRestart(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	config := testConfig()
	config.Port = uint32(port)
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	config.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(key)
	tracker := newConnectionTracker()
	kernel, err := newSingBoxKernel(context.Background(), VlessRuntimeConfig(config), nil, tracker)
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Close()
	address := fmt.Sprintf("127.0.0.1:%d", port)
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("empty kernel did not listen: %v", err)
	}
	_ = connection.Close()

	if err := kernel.UpdateUsers([]kernelUser{{Name: "m1.g1", Secret: testUUIDA}}); err != nil {
		t.Fatal(err)
	}
	connection, err = net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("hot update stopped the listener: %v", err)
	}
	_ = connection.Close()
	if err := kernel.Close(); err != nil {
		t.Fatal(err)
	}
	connection, err = net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("kernel listener remained open after close")
	}
}
