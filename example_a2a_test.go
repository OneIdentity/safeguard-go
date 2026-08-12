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
	"encoding/json"
	"fmt"
	"log"
	"os"

	safeguard "github.com/OneIdentity/safeguard-go"
)

// ExampleA2AContext_RetrievePassword retrieves an account password over the
// Application-to-Application service. An A2AContext authenticates with a client
// certificate on every call; the per-account API key selects which registered
// account the call targets.
func ExampleA2AContext_RetrievePassword() {
	ctx := context.Background()

	certPEM, err := os.ReadFile("a2a-client.pem")
	if err != nil {
		log.Fatal(err)
	}
	a2a, err := safeguard.NewA2AContext("safeguard.example.com", certPEM, safeguard.Secret{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a2a.Close() }()

	apiKey := safeguard.NewSecretString(os.Getenv("A2A_API_KEY"))
	defer apiKey.Zero()

	password, err := a2a.RetrievePassword(ctx, apiKey)
	if err != nil {
		log.Fatal(err)
	}
	defer password.Zero()

	// Use password.Expose()/ExposeString() where the plaintext is required; do
	// not log it. Here we only report that a value was retrieved.
	fmt.Printf("retrieved a %d-byte password\n", password.Len())
}

// ExampleA2AContext_GetRetrievableAccounts discovers every account the context's
// client certificate is registered to retrieve, along with the API key that
// authorizes each retrieval.
func ExampleA2AContext_GetRetrievableAccounts() {
	ctx := context.Background()

	certPEM, err := os.ReadFile("a2a-client.pem")
	if err != nil {
		log.Fatal(err)
	}
	a2a, err := safeguard.NewA2AContext("safeguard.example.com", certPEM, safeguard.Secret{})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a2a.Close() }()

	accounts, err := a2a.GetRetrievableAccounts(ctx, "")
	if err != nil {
		log.Fatal(err)
	}
	for _, acct := range accounts {
		fmt.Printf("%s on %s\n", acct.AccountName, acct.AssetName)
		// acct.APIKey can be passed straight to RetrievePassword and friends.
	}
}

// ExampleClient_NewPersistentEventListener subscribes to Safeguard events and
// keeps the subscription alive across reconnects until the listener is stopped.
func ExampleClient_NewPersistentEventListener() {
	var client *safeguard.Client // obtained from safeguard.Connect
	ctx := context.Background()

	listener := client.NewPersistentEventListener()
	listener.RegisterEventHandler("AssetAccountPasswordUpdated", func(name string, data json.RawMessage) {
		fmt.Printf("event %s: %s\n", name, data)
	})

	if err := listener.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer listener.Stop()

	// Block until the listener stops (context cancelled, or a terminal error).
	<-listener.Done()
	if err := listener.Err(); err != nil {
		log.Printf("listener stopped: %v", err)
	}
}
