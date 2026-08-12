---
name: testing-guide
description: Reference for unit, fuzz, race, and live-appliance integration test strategy.
---

# Testing Guide

The test strategy is: fast unit tests with fake HTTP/TLS/WS servers, fuzzing for the SignalR frame parser, race tests for token/session concurrency, and gated integration tests.

## Live appliance end-to-end is the standard

Live-appliance e2e is the authoritative proof that a feature works. Fake-server unit tests are a required fast supplement for logic, edge cases, and error mapping, but every auth flow and connection-lifecycle behavior must also be proven against a running Safeguard before it is considered done.

- Live tests live in-package alongside unit tests and **skip** (never fail) when `SPP_HOST` is unset, so `go test ./...` stays hermetic by default.
- The reference appliance is `spp1.dan.laptop` (192.168.99.15) with bootstrap `Admin`/`Admin123`. It has **Resource Owner Grant disabled**, so PKCE-headless is the primary automation login; password-login live tests must detect the ROG-disabled response (`grant type is not allowed`) and skip rather than fail.
- Live tests pin the appliance leaf certificate by default and honor `SPP_INSECURE` / `SPP_CA_BUNDLE` for bootstrap trust.

## Unit, fuzz, race

- Unit tests use `httptest.Server`, fake TLS/WebSocket servers, table-driven cases, and `package safeguard_test` for cross-package coverage.
- Fuzz the SignalR frame parser for coalesced records, record separators, oversized frames, and malformed input.
- Run `go test -race ./...` for refresh/logout/401/event concurrency paths.
- Live tests skip when `SPP_HOST` is unset, provision/cleanup resources with bootstrap credentials, and handle ROG-disabled appliances without false failures.

### Encrypted PKCS#8 key fixtures

`pkcs8_encrypted_test.go` embeds encrypted-key fixtures as raw-string constants so the tests stay hermetic (no OpenSSL at test time). They cover the PBES2 ciphers, PRFs, and KDFs seen in practice across RSA, EC, and Ed25519 keys, and each decrypts to its reference key under `pkcs8TestPassword`. Regenerate with OpenSSL 3.x from an unencrypted PKCS#8 key (`openssl genpkey ... -out plain.pem`):

```sh
# AES-128/192/256-CBC with PBKDF2 (default PRF is hmacWithSHA256); vary with -v2prf
openssl pkcs8 -topk8 -in plain.pem -passout pass:sg-unit-test-pw -v2 aes-256-cbc -v2prf hmacWithSHA256
openssl pkcs8 -topk8 -in plain.pem -passout pass:sg-unit-test-pw -v2 aes-128-cbc -v2prf hmacWithSHA1
openssl pkcs8 -topk8 -in plain.pem -passout pass:sg-unit-test-pw -v2 des3      # 3DES (des-ede3-cbc)
openssl pkcs8 -topk8 -in plain.pem -passout pass:sg-unit-test-pw -scrypt       # scrypt KDF
```

The decryptor itself lives in `pkcs8_encrypted.go`, isolated so it can be replaced if the standard library or `x/crypto` ever grows a first-class equivalent.

## CI vs. local

CI runs only hermetic checks (build, format, vet, lint, race-enabled unit tests); it never runs the live tests because no appliance is reachable from the hosted agents. Running the live suite is therefore a **local developer responsibility** and a recommended part of validating any change to an auth flow, the transport/refresh/token lifecycle, A2A, or events — run `go test ./...` with `SPP_HOST` set against a lab appliance and confirm it is green before considering the change done.
