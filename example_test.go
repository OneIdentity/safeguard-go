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

package safeguard_test

import (
	"context"
	"fmt"
	"log"
	"os"

	safeguard "github.com/OneIdentity/safeguard-go"
)

// Example shows the canonical flow: build a credential, Connect, make a call,
// and Close. The client owns an in-memory token that Close releases.
func Example() {
	ctx := context.Background()

	password := safeguard.NewSecretString("correct horse battery staple")
	defer password.Zero()

	client, err := safeguard.Connect(ctx, "safeguard.example.com",
		safeguard.UsernamePassword("local", "Admin", password))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	resp, err := client.Get(ctx, safeguard.Core, "Me")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("GET Me -> %d\n", resp.StatusCode)
}

// ExampleConnect_certificate authenticates with a client certificate over mutual
// TLS. The PEM material carries the leaf certificate, any chain, and the private
// key; password decrypts an encrypted key and may be empty otherwise.
func ExampleConnect_certificate() {
	ctx := context.Background()

	certPEM, err := os.ReadFile("client.pem")
	if err != nil {
		log.Fatal(err)
	}
	keyPassword := safeguard.NewSecretString("key-passphrase")
	defer keyPassword.Zero()

	client, err := safeguard.Connect(ctx, "safeguard.example.com",
		safeguard.Certificate(certPEM, keyPassword))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()
}

// ExampleConnect_pkce authenticates with the PKCE non-interactive ("headless")
// flow, which does not depend on the Resource Owner Grant and is the recommended
// flow for automation.
func ExampleConnect_pkce() {
	ctx := context.Background()

	password := safeguard.NewSecretString("correct horse battery staple")
	defer password.Zero()

	client, err := safeguard.Connect(ctx, "safeguard.example.com",
		safeguard.PKCEHeadless("local", "Admin", password))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()
}

// ExampleConnect_token reuses an existing Safeguard user token. Such a session is
// not refreshable, so a 401 is surfaced rather than silently retried.
func ExampleConnect_token() {
	ctx := context.Background()

	userToken := safeguard.NewSecretString(os.Getenv("SAFEGUARD_TOKEN"))
	defer userToken.Zero()

	client, err := safeguard.Connect(ctx, "safeguard.example.com",
		safeguard.Token(userToken))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()
}

// ExampleClient_Get retrieves a resource and reads the raw response body. Get is
// shorthand for Invoke with the GET method and no request body.
func ExampleClient_Get() {
	var client *safeguard.Client // obtained from safeguard.Connect
	ctx := context.Background()

	resp, err := client.Get(ctx, safeguard.Core, "Users",
		safeguard.WithQueryParam("filter", "Disabled eq false"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d: %s\n", resp.StatusCode, resp.Body)
}

// ExampleInvokeTyped decodes a successful JSON response directly into a Go value.
func ExampleInvokeTyped() {
	var client *safeguard.Client // obtained from safeguard.Connect
	ctx := context.Background()

	type me struct {
		UserName    string `json:"UserName"`
		DisplayName string `json:"DisplayName"`
	}

	info, err := safeguard.InvokeTyped[me](ctx, client, safeguard.MethodGet, safeguard.Core, "Me", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("signed in as %s (%s)\n", info.UserName, info.DisplayName)
}

// ExampleClient_Download streams a response body to an io.Writer without
// buffering it in memory, which suits large payloads such as backups or reports.
func ExampleClient_Download() {
	var client *safeguard.Client // obtained from safeguard.Connect
	ctx := context.Background()

	f, err := os.Create("backup.sgb")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if _, err := client.Download(ctx, safeguard.Appliance, "Backups/current/Download", f); err != nil {
		log.Fatal(err)
	}
}
