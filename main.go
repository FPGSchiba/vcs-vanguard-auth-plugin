package main

import (
	"flag"
	"fmt"
	pb "github.com/FPGSchiba/vcs-vanguard-auth-plugin/vcsauthpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"log"
	"net"
	"time"
)

// TODO: Make this a go Module and import the state package properly
const (
	DistributionModeStandalone uint8 = iota // Standalone mode, no distribution all in one Server
	DistributionModeControl                 // Only Control Server, no Voice. Used as Control-Node for Voice Servers
	DistributionModeVoice                   // Only Voice Server, no Control. Used as Voice-Node for Control Servers
)

const version = "0.1.0"

func main() {
	var port int
	var distributionMode int
	flag.IntVar(&port, "port", 16057, "port to listen on")
	flag.IntVar(&distributionMode, "distribution-mode", int(DistributionModeStandalone), "distribution mode: 0=standalone, 1=control, 2=voice")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port)) // Listen only on localhost as it is a plugin
	if err != nil {
		log.Fatalf("Error starting server: %v\n", err)
		return
	}

	grpcServer := grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // allow pings every 10s
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second, // server sends pings every 20s if idle
			Timeout: 10 * time.Second, // wait 10s for ping ack
		}),
	)

	pluginServer := NewVanguardAuthPluginServer(uint8(distributionMode))
	pb.RegisterAuthPluginServiceServer(grpcServer, pluginServer)

	log.Printf("Vanguard Auth Plugin Server v%s started on port %d with distribution mode %d\n", version, port, distributionMode)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Error serving gRPC server: %v\n", err)
		return
	}
}
