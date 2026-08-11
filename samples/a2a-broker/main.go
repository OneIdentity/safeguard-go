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

// Command a2a-broker demonstrates brokering an access request on behalf of
// another user. The broker application authenticates with its client certificate
// over mutual TLS and presents its broker API key, then creates an access
// request for a named user, asset, and account.
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
	certFile := flag.String("cert", "", "path to the broker client certificate PEM (leaf, chain, and optionally the key)")
	keyFile := flag.String("key", "", "path to the private key PEM, when it is not in the -cert file")
	certPassword := flag.String("cert-password", "", "password for an encrypted PEM private key")
	brokerKeyFlag := flag.String("broker-apikey", "", "the broker API key that authorizes the request")
	forUser := flag.String("for-user", "", "user the access request is made for")
	assetName := flag.String("asset", "", "target asset name")
	accountName := flag.String("account", "", "target account name")
	flag.Parse()

	if *appliance == "" || *certFile == "" || *brokerKeyFlag == "" || *forUser == "" || *assetName == "" || *accountName == "" {
		log.Fatal("-appliance, -cert, -broker-apikey, -for-user, -asset, and -account are required")
	}
	brokerKey := safeguard.NewSecretString(*brokerKeyFlag)
	defer brokerKey.Zero()

	ctx := context.Background()
	a2a, err := newA2AContext(*appliance, *certFile, *keyFile, *certPassword, *caFile, *insecure)
	if err != nil {
		log.Fatalf("build A2A context: %v", err)
	}
	defer func() { _ = a2a.Close() }()

	req := safeguard.BrokeredAccessRequest{
		AccessRequestType: safeguard.AccessRequestPassword,
		ForUser:           *forUser,
		AssetName:         *assetName,
		AccountName:       *accountName,
	}
	request, err := a2a.BrokerAccessRequest(ctx, brokerKey, req)
	if err != nil {
		log.Fatalf("broker access request: %v", err)
	}
	fmt.Printf("Created access request %s (state %s)\n", request.ID, request.State)
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
