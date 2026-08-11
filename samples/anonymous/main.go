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

// Command anonymous demonstrates an anonymous session, which carries no user
// token and is sufficient for the Notification service and other unauthenticated
// endpoints such as the appliance status.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/OneIdentity/safeguard-go"
)

func main() {
	appliance := flag.String("appliance", "", "Safeguard appliance host name or IP")
	caFile := flag.String("ca", "", "path to the appliance's trusted CA bundle (PEM); empty uses the system trust store")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev/test only)")
	flag.Parse()

	if *appliance == "" {
		log.Fatal("-appliance is required")
	}

	opts, err := connectionOptions(*caFile, *insecure)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	client, err := safeguard.Connect(ctx, *appliance, safeguard.Anonymous(), opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(ctx, safeguard.Notification, "Status")
	if err != nil {
		log.Fatalf("GET Status: %v", err)
	}
	fmt.Printf("GET Status -> %d\n%s\n", resp.StatusCode, resp.Body)
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
