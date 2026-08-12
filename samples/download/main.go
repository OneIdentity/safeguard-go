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

// Command download demonstrates Download, which streams a response body straight
// to an io.Writer without buffering it in memory — suited to large payloads such
// as backups or reports. It signs in with the PKCE headless flow and writes the
// response to a file.
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
	provider := flag.String("provider", "local", "authentication provider")
	username := flag.String("username", "", "user name")
	passwordFlag := flag.String("password", "", "password")
	service := flag.String("service", "appliance", "service: core or appliance")
	relURL := flag.String("relurl", "", "relative URL of the download endpoint (required)")
	out := flag.String("out", "", "path to write the downloaded body to (required)")
	flag.Parse()

	if *appliance == "" || *username == "" || *relURL == "" || *out == "" {
		log.Fatal("-appliance, -username, -relurl, and -out are required")
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

	// #nosec G304 -- a sample intentionally writes to a caller-provided path.
	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("create output file: %v", err)
	}
	defer func() { _ = f.Close() }()

	resp, err := client.Download(ctx, safeguard.Service(*service), *relURL, f)
	if err != nil {
		log.Fatalf("download: %v", err)
	}
	fmt.Printf("Downloaded %s -> %d, wrote %s\n", *relURL, resp.StatusCode, *out)
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
