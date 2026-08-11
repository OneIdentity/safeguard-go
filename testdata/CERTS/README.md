# testdata/CERTS

Throwaway certificate fixtures for the certificate-login end-to-end test
(`certificate_live_test.go`). They are **test data only** and carry no security
value: the private key is unencrypted and committed on purpose so the live
suite can run unattended.

| File | Contents |
|---|---|
| `user-cert.pem` | Self-signed client certificate (RSA 2048, `CN=SgGo_CertAuthTest`, `clientAuth` EKU, valid 2020-2120). |
| `user-key.pem` | The matching unencrypted PKCS#8 private key. |

The e2e test uploads `user-cert.pem` to the appliance as a trusted certificate,
creates a temporary certificate-authentication user mapped to the certificate's
SHA-1 thumbprint, logs in with the certificate over mutual TLS, and then deletes
both the user and the trusted certificate. This mirrors how PySafeguard,
SafeguardDotNet, and SafeguardJava provision certificate auth for their live
tests, adapted to this SDK's PEM-only certificate input.

To regenerate (only needed if you want a different subject or validity), run the
generator kept with the session notes, or any equivalent that emits a self-signed
`clientAuth` certificate and its unencrypted PKCS#8 key as PEM.
