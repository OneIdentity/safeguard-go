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

// Command invoke is a small general-purpose client that issues one request with
// any HTTP method against any Safeguard service, demonstrating the generic Invoke
// surface (Get/Post/Put/Delete). It signs in with the PKCE headless flow. The
// default method is GET; supply -method and -body to make a mutating call.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/OneIdentity/safeguard-go"
)

func main() {
	appliance := flag.String("appliance", "", "Safeguard appliance host name or IP")
	caFile := flag.String("ca", "", "path to the appliance's trusted CA bundle (PEM); empty uses the system trust store")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev/test only)")
	provider := flag.String("provider", "local", "authentication provider")
	username := flag.String("username", "", "user name")
	passwordFlag := flag.String("password", "", "password")
	method := flag.String("method", "GET", "HTTP method: GET, POST, PUT, or DELETE")
	service := flag.String("service", "core", "service: core, appliance, or notification")
	relURL := flag.String("relurl", "", "relative URL, e.g. Users or Users/5 (required)")
	body := flag.String("body", "", "request body (JSON) for POST/PUT")
	flag.Parse()

	if *appliance == "" || *username == "" || *relURL == "" {
		log.Fatal("-appliance, -username, and -relurl are required")
	}
	password := safeguard.NewSecretString(*passwordFlag)
	defer password.Zero()

	opts, err := connectionOptions(*caFile, *insecure)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	cred := safeguard.PKCEHeadless(*provider, *username, password)
	client, err := safeguard.Connect(ctx, *appliance, cred, opts...)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Service and HTTPMethod are string types whose values match the service
	// path segment and the HTTP verb, so the flags map onto them directly.
	svc := safeguard.Service(strings.ToLower(*service))
	m := safeguard.HTTPMethod(strings.ToUpper(*method))

	var reqBody any
	if *body != "" {
		reqBody = *body
	}

	resp, err := client.Invoke(ctx, m, svc, *relURL, reqBody)
	if err != nil {
		// Invoke returns the populated FullResponse alongside a typed error on a
		// non-2xx status, so the status and body are still worth printing.
		log.Fatalf("%s %s %s -> %d: %v", m, svc, *relURL, resp.StatusCode, err)
	}
	fmt.Printf("%s %s %s -> %d\n%s\n", m, svc, *relURL, resp.StatusCode, resp.Body)
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
