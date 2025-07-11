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

const version = "0.1.0"

func main() {
	var port int
	flag.IntVar(&port, "port", 16057, "port to listen on")
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

	pluginServer := NewVanguardAuthPluginServer()
	pb.RegisterAuthPluginServiceServer(grpcServer, pluginServer)

	log.Printf("Vanguard Auth Plugin Server v%s started on port %d\n", version, port)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Error serving gRPC server: %v\n", err)
		return
	}
}
