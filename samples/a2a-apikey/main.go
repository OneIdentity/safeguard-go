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

// Command a2a-apikey demonstrates Application-to-Application (A2A) API-key secret
// retrieval. The application authenticates with its client certificate over
// mutual TLS and presents an API key that authorizes retrieval of one account's
// API-key credentials.
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
	certFile := flag.String("cert", "", "path to the A2A client certificate PEM (leaf, chain, and optionally the key)")
	keyFile := flag.String("key", "", "path to the private key PEM, when it is not in the -cert file")
	certPassword := flag.String("cert-password", "", "password for an encrypted PEM private key")
	apiKeyFlag := flag.String("apikey", "", "the A2A API key that authorizes retrieval")
	flag.Parse()

	if *appliance == "" || *certFile == "" || *apiKeyFlag == "" {
		log.Fatal("-appliance, -cert, and -apikey are required")
	}
	apiKey := safeguard.NewSecretString(*apiKeyFlag)
	defer apiKey.Zero()

	ctx := context.Background()
	a2a, err := newA2AContext(*appliance, *certFile, *keyFile, *certPassword, *caFile, *insecure)
	if err != nil {
		log.Fatalf("build A2A context: %v", err)
	}
	defer func() { _ = a2a.Close() }()

	secrets, err := a2a.RetrieveAPIKeySecret(ctx, apiKey)
	if err != nil {
		log.Fatalf("retrieve API key secret: %v", err)
	}

	for _, s := range secrets {
		// A real application would use ClientSecret, not print it.
		fmt.Printf("API key %q (ClientId %s): %s\n", s.Name, s.ClientID, s.ClientSecret.ExposeString())
		s.ClientSecret.Zero()
	}
}

// newA2AContext builds an A2AContext from the certificate, key, and TLS flags
// shared by the A2A samples.
func newA2AContext(appliance, certFile, keyFile, certPassword, caFile string, insecure bool) (*safeguard.A2AContext, error) {
	// #nosec G304 -- a sample intentionally reads a caller-provided certificate path.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	password := safeguard.NewSecretString(certPassword)
	defer password.Zero()

	var a2aOpts []safeguard.A2AOption
	if keyFile != "" {
		// #nosec G304 -- a sample intentionally reads a caller-provided key path.
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}
		a2aOpts = append(a2aOpts, safeguard.WithA2APrivateKeyPEM(keyPEM))
	}

	connOpts, err := connectionOptions(caFile, insecure)
	if err != nil {
		return nil, err
	}
	if len(connOpts) > 0 {
		a2aOpts = append(a2aOpts, safeguard.WithA2AConnectionOptions(connOpts...))
	}
	return safeguard.NewA2AContext(appliance, certPEM, password, a2aOpts...)
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
