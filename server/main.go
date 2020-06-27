/*
 * Copyright @ 2020 - present Blackvisor Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"time"

	api "github.com/netclave/apis/opener/api"
	"github.com/netclave/opener/component"
	"github.com/netclave/opener/config"
	"github.com/netclave/opener/handlers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func startGRPCServer(address string) error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// create a listener on TCP port
	lis, err := net.Listen("tcp", address)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	// create a server instance
	s := handlers.Server{}

	ServerMaxReceiveMessageSize := math.MaxInt32

	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(ServerMaxReceiveMessageSize)}
	// create a gRPC server object
	grpcServer := grpc.NewServer(opts...)

	// attach the Ping service to the server
	api.RegisterOpenerAdminServer(grpcServer, &s)

	// start the server
	log.Printf("starting HTTP/2 gRPC server on %s", address)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %s", err)
	}

	return nil
}

func startFirewallDaemon() error {
	configuration, err := component.CreateFirewallConfiguration()

	if err != nil {
		return err
	}

	for {
		rules, err := handlers.ListOpenerRulesInternal("all")

		if err != nil {
			log.Println(err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		for _, rule := range rules {
			ip := rule.IP
			port := rule.Port
			protocols := rule.Protocols

			tokenProtocols := strings.Split(protocols, ",")

			for _, protocol := range tokenProtocols {
				protocolPort := protocol + ":" + port
				configuration.AddPortForIP(ip, protocolPort)
			}
		}

		err = configuration.LoadCurrentPolicy()

		if err != nil {
			log.Println(err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		err = configuration.FlushNewPolicy()

		if err != nil {
			log.Println(err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		time.Sleep(2 * time.Second)
	}

	return nil
}

func main() {
	err := component.LoadComponent()
	if err != nil {
		log.Println(err.Error())
		return
	}

	go func() {
		err := startFirewallDaemon()

		if err != nil {
			log.Println(err.Error())
		}
	}()

	log.Println("Starting grpc server")
	err = startGRPCServer(config.ListenGRPCAddress)
}
