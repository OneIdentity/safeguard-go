# testdata/CERTS

Throwaway certificate fixtures for the certificate-login end-to-end test
(`certificate_live_test.go`). They are **test data only** and carry no security
value: the private keys are committed on purpose (one unencrypted, one encrypted
with a known password documented below) so the live suite can run unattended.

| File | Contents |
|---|---|
| `user-cert.pem` | Self-signed client certificate (RSA 2048, `CN=SgGo_CertAuthTest`, `clientAuth` EKU, valid 2020-2120). |
| `user-key.pem` | The matching unencrypted PKCS#8 private key. |
| `user-key-encrypted.pem` | The same private key encrypted as PKCS#8 (PBES2: AES-256-CBC, PBKDF2-HMAC-SHA256) with password `sg-live-test-pw`. Used by the encrypted-key certificate login e2e test. |

The e2e test uploads `user-cert.pem` to the appliance as a trusted certificate,
creates a temporary certificate-authentication user mapped to the certificate's
SHA-1 thumbprint, logs in with the certificate over mutual TLS, and then deletes
both the user and the trusted certificate. This mirrors how PySafeguard,
SafeguardDotNet, and SafeguardJava provision certificate auth for their live
tests, adapted to this SDK's PEM-only certificate input.

To regenerate (only needed if you want a different subject or validity), run the
generator kept with the session notes, or any equivalent that emits a self-signed
`clientAuth` certificate and its unencrypted PKCS#8 key as PEM. Regenerate the
encrypted variant from the unencrypted key with:

```sh
openssl pkcs8 -topk8 -in user-key.pem -passout pass:sg-live-test-pw \
  -v2 aes-256-cbc -v2prf hmacWithSHA256 -out user-key-encrypted.pem
```
