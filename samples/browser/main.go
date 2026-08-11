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

// Command browser demonstrates an interactive external-browser (PKCE) login.
// The SDK starts a loopback listener, opens the system browser to the
// appliance's login page, and completes the login when the browser redirects
// back. It lives in the browser add-on package so headless applications keep a
// lean dependency graph.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/OneIdentity/safeguard-go"
	"github.com/OneIdentity/safeguard-go/browser"
)

func main() {
	appliance := flag.String("appliance", "", "Safeguard appliance host name or IP")
	caFile := flag.String("ca", "", "path to the appliance's trusted CA bundle (PEM); empty uses the system trust store")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev/test only)")
	loginHint := flag.String("username", "", "optional login hint to pre-fill the user name")
	flag.Parse()

	if *appliance == "" {
		log.Fatal("-appliance is required")
	}

	connOpts, err := connectionOptions(*caFile, *insecure)
	if err != nil {
		log.Fatal(err)
	}

	opts := []browser.Option{browser.WithConnectionOptions(connOpts...)}
	if *loginHint != "" {
		opts = append(opts, browser.WithLoginHint(*loginHint))
	}

	ctx := context.Background()
	fmt.Println("Opening your browser to complete the login...")
	client, err := browser.Connect(ctx, *appliance, opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(ctx, safeguard.Core, "Me")
	if err != nil {
		log.Fatalf("GET Me: %v", err)
	}
	fmt.Printf("GET Me -> %d\n%s\n", resp.StatusCode, resp.Body)
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
