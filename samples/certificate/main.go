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

// Command certificate demonstrates a client-certificate login over mutual TLS.
// The certificate and key are supplied as PEM files; convert a PKCS#12 (.pfx)
// first, for example: openssl pkcs12 -in cert.pfx -nodes -out cert.pem.
package main

import (
	"context"
	"crypto/tls"
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
	certFile := flag.String("cert", "", "path to the client certificate PEM (leaf, chain, and optionally the key)")
	keyFile := flag.String("key", "", "path to the private key PEM, when it is not in the -cert file")
	certPasswordFlag := flag.String("cert-password", "", "password for an encrypted PEM private key")
	provider := flag.String("provider", "", "certificate authentication provider (empty uses the default)")
	// Certificate auth defaults to TLS 1.2 (Go cannot present a client cert in
	// response to a TLS 1.3 post-handshake request), so no flags are needed
	// against a 9.0 Standard binding. To use TLS 1.3 cert-auth, connect to the
	// appliance Cert SNI hostname and pass -max-tls 1.3.
	minTLS := flag.String("min-tls", "", "minimum TLS version: 1.0, 1.1, 1.2, or 1.3 (empty uses the default floor of 1.2)")
	maxTLS := flag.String("max-tls", "", "maximum TLS version: 1.0, 1.1, 1.2, or 1.3 (empty caps cert-auth at 1.2; set 1.3 for the Cert SNI hostname)")
	flag.Parse()

	if *appliance == "" || *certFile == "" {
		log.Fatal("-appliance and -cert are required")
	}

	// #nosec G304 -- a sample intentionally reads a caller-provided certificate path.
	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("read certificate: %v", err)
	}
	certPassword := safeguard.NewSecretString(*certPasswordFlag)
	defer certPassword.Zero()

	var certOpts []safeguard.CertOption
	if *keyFile != "" {
		// #nosec G304 -- a sample intentionally reads a caller-provided key path.
		keyPEM, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("read key: %v", err)
		}
		certOpts = append(certOpts, safeguard.WithPrivateKeyPEM(keyPEM))
	}
	if *provider != "" {
		certOpts = append(certOpts, safeguard.WithCertificateProvider(*provider))
	}

	opts, err := connectionOptions(*caFile, *insecure, *minTLS, *maxTLS)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	cred := safeguard.Certificate(certPEM, certPassword, certOpts...)
	client, err := safeguard.Connect(ctx, *appliance, cred, opts...)
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

// connectionOptions builds the TLS-related connection options for the sample
// from the -ca, -insecure, and -min-tls/-max-tls flags.
func connectionOptions(caFile string, insecure bool, minTLS, maxTLS string) ([]safeguard.Option, error) {
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
	if minTLS != "" {
		v, err := parseTLSVersion(minTLS)
		if err != nil {
			return nil, fmt.Errorf("-min-tls: %w", err)
		}
		opts = append(opts, safeguard.WithMinTLSVersion(v))
	}
	if maxTLS != "" {
		v, err := parseTLSVersion(maxTLS)
		if err != nil {
			return nil, fmt.Errorf("-max-tls: %w", err)
		}
		opts = append(opts, safeguard.WithMaxTLSVersion(v))
	}
	return opts, nil
}

// parseTLSVersion maps a "1.0".."1.3" string to a crypto/tls version constant.
func parseTLSVersion(s string) (uint16, error) {
	switch s {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unrecognized TLS version %q (want 1.0, 1.1, 1.2, or 1.3)", s)
	}
}
