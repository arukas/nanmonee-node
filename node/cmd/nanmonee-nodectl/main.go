package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	nodev1 "nanmonee/node/api/node/v1"
	"nanmonee/node/internal/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	configPath := flag.String("config", "", "path to the owner-only startup config")
	operation := flag.String("op", "status", "status, usage, or apply")
	snapshotPath := flag.String("snapshot", "", "path to an ApplySnapshot JSON message")
	timeout := flag.Duration("timeout", 5*time.Second, "RPC deadline")
	flag.Parse()
	startup, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	connection, err := grpc.NewClient(startup.Control.Listen, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+startup.Control.Secret), *timeout)
	defer cancel()
	client := nodev1.NewNodeControlClient(connection)
	var response proto.Message
	switch *operation {
	case "status":
		response, err = client.GetStatus(ctx, &nodev1.GetStatusRequest{})
	case "usage":
		response, err = client.GetUsageSnapshot(ctx, &nodev1.GetUsageSnapshotRequest{})
	case "apply":
		if *snapshotPath == "" {
			log.Fatal("the -snapshot option is required for apply")
		}
		content, readErr := os.ReadFile(*snapshotPath)
		if readErr != nil {
			log.Fatal(readErr)
		}
		request := new(nodev1.ApplySnapshotRequest)
		if unmarshalErr := (protojson.UnmarshalOptions{}).Unmarshal(content, request); unmarshalErr != nil {
			log.Fatal(unmarshalErr)
		}
		if request.ExpectedRuntimeId == "" {
			current, statusErr := client.GetStatus(ctx, &nodev1.GetStatusRequest{})
			if statusErr != nil {
				log.Fatal(statusErr)
			}
			request.ExpectedRuntimeId = current.Status.RuntimeId
			request.ExpectedStateRevision = current.Status.StateRevision
		}
		response, err = client.ApplySnapshot(ctx, request)
	default:
		log.Fatal("unsupported operation")
	}
	if err != nil {
		log.Fatal(err)
	}
	encoded, err := (protojson.MarshalOptions{Multiline: true, Indent: "  "}).Marshal(response)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}
