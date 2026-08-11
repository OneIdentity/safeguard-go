// Copyright 2026 One Identity LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command events-persistent demonstrates a reconnecting SignalR event listener.
// It re-establishes the connection after a drop and restores registered handlers
// until the session is terminally ended or you press Ctrl+C.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/OneIdentity/safeguard-go"
)

func main() {
	appliance := flag.String("appliance", "", "Safeguard appliance host name or IP")
	caFile := flag.String("ca", "", "path to the appliance's trusted CA bundle (PEM); empty uses the system trust store")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev/test only)")
	provider := flag.String("provider", "local", "authentication provider")
	username := flag.String("username", "", "user name")
	passwordFlag := flag.String("password", "", "password")
	event := flag.String("event", "AssetAccountPasswordUpdated", "event name to subscribe to")
	flag.Parse()

	if *appliance == "" || *username == "" {
		log.Fatal("-appliance and -username are required")
	}
	password := safeguard.NewSecretString(*passwordFlag)
	defer password.Zero()

	opts, err := connectionOptions(*caFile, *insecure)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cred := safeguard.PKCEHeadless(*provider, *username, password)
	client, err := safeguard.Connect(ctx, *appliance, cred, opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	listener := client.NewPersistentEventListener()
	listener.RegisterEventHandler(*event, func(name string, data json.RawMessage) {
		fmt.Printf("event %s: %s\n", name, data)
	})

	if err := listener.Start(ctx); err != nil {
		log.Fatalf("start listener: %v", err)
	}
	fmt.Printf("Listening for %q events (auto-reconnecting). Press Ctrl+C to stop.\n", *event)

	<-listener.Done()
	if err := listener.Err(); err != nil && ctx.Err() == nil {
		log.Fatalf("listener stopped: %v", err)
	}
}

// connectionOptions builds the TLS-related connection options shared by the
// samples from the -ca and -insecure flags.
func connectionOptions(caFile string, insecure bool) ([]safeguard.Option, error) {
	var opts []safeguard.Option
	if caFile != "" {
		// #nosec G304 -- a sample intentionally reads a caller-provided CA path.
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		opts = append(opts, safeguard.WithCABundle(pemBytes))
	}
	if insecure {
		opts = append(opts, safeguard.WithInsecureTLS())
	}
	return opts, nil
}
