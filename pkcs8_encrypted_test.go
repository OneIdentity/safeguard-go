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

package safeguard

// The encrypted-key fixtures below were generated with OpenSSL 3.x using
// `openssl pkcs8 -topk8` across the PBES2 ciphers, PRFs, and KDFs that appear in
// practice, plus RSA, EC, and Ed25519 keys. Each decrypts to the matching
// reference key under pkcs8TestPassword. Regenerate with the commands documented
// in the testing-guide skill if these ever need to change.

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

const pkcs8TestPassword = "sg-unit-test-pw" //nolint:gosec // fixed password for the encrypted-key test fixtures below; not a real credential.
const ecPlainPKCS8 = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgr8gKuFu/csXVDR/a
83DgLyF+3wN+ks1Igs3QXshwwp2hRANCAAQDYOfJIniTVUt19Gnl56YJBtglZVIj
ruj+g0Og2sY5dXC60FTE2g3R4Yx2voqVNW2vuaoaE9Ti9IBD2qOOu4jh
-----END PRIVATE KEY-----
`

const rsaPlainPKCS8 = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzLDGk8zr0Wt3h
ZIMAPycnH8cuWkAS/TLZlcaDh8bMkkcNf2owlNevyZaTtTjlQjH7Jy5C7nCJxs/5
xrI+KylR7yliEracoL404QiX+Y/lya+EGHuI7XreFeLfaaMvvM77NDyTEFSCM91v
lTXKxPl6lUVMjUgTsL3pYFd/I/bqnjU0oGmdFaiCkMkrx9Fu07Qq3pzVOIgVfxFw
N9xMUWfaxjemcao+Xi0fws+HC1MpcrRSpuH02XGrXjyzE1Uq6kZuAFpAT5G7mLG2
2IScP1CnOf/T4QGrVR3puBJDag2aLV7A9C5tLJHpQvhGCGCsOWfnO4PkrTfKux8y
uUwYidiLAgMBAAECggEAGLm8kBrQw+/WNsh8G4ibipakEg16UiSG4+f7YSNXl9uH
2qD+sn2X1jZnhTK5C0o7Q4GArNPiy+CXysxUxKeIKDps54/Vi3/TP9DeMrrJ1Ngk
VIJcaeT707IJgPM/BdN0bM4kndbfEqi9oixhI/5Sv0viKFJG5BC75HzbFjyMUowP
X/QEqqXKGV2NzWhcRPoJL6WYG9M1cBY+1wTGEY3rcTTmwDjGJO7xOOYsGuXf4dr7
iyQ0SZc5r2Wk9rLIkDfXGSXq0P+vDMZs4NLomg/NA0o5403ZCnPRAWboaLmFkHVd
9Zz/fTBv4IO9ebULePsK8Bxv9/z8xFD0hNkS5nB2YQKBgQDmKvMFszqXIcSaiWZl
qc3JlviMBDWEbLyaMejqjWexjlRqhi7ZWWINSJT654WitoRgz4gTCQGsbroytlwx
yDECVw3MICmz0qL8uzefEXcM1hZrNX5pZWy8e/kOOXJ5cHWp0e1grfoTIYiuu0RC
KZWPO0ty2XX6jM3eVVFToC3jBQKBgQDHSBS/GMY2px6iCghhFrSsXrfDjq6DZWZx
4tWJg3h1rBv6f0UDdRaryknhuhLqFnV58sQ+vGpqlVB4JQfGV/S6YYiUCz5vY+Eq
pOefFtRK+c7bADfmRq0RAUegTH0BXkitt1mKFw+0iOYpdWiZwRGQHmzWYbEpDRQQ
zodXQKvCTwKBgQC5cvmEKjiW9Lo32WULnJkWR/HSvsFwBTyg8H2+HljiEs+pVJwC
u6XpFgYTct+VjoFyj0QQMj2K9VxI5+24npf+Tq3rPi7bmGeCQkY6gBPv378Ien1z
5iiKZUjyUQ8PEbF8NoyQTR0ktOwv/OqudFrwoNHVo6kPSsvEy/FO88yFEQKBgFPP
6gHQ/pQ/xy9pPsrujMAt+eWCXb0faW2edCaop4H+B6pb2n+wv/8yTc5kvs268l9+
jbDA95SqBbTyBgoSNfgpSxLQg8q/XBTeVBfhtxltZOVQezIbKXCMdD5jzPNFXxXI
lhzwxAcuyHZJTdvUinltgmLLpYHZYUYMRnmY1mQbAoGBAOMHP0+0aPIS/b0azKR/
KoZf8M6D9jejbFBVBH8ofln7v9cjnDoaumf9zyW4kV13pQnPHWg5ldadeh/PwPpK
1cnRRROeNjvicbkHpJvu3BN0Uf6+5BM2JnF85zoDFH3eCBZcoMULw4CtRbB0EPOp
popISsfiundYioFKOHY1n7kS
-----END PRIVATE KEY-----
`

const edPlainPKCS8 = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICN10T6i5WiD79y7HPemMq0v4+2ElernjhefUZgqVcxL
-----END PRIVATE KEY-----
`

const ecCertPEM = `
-----BEGIN CERTIFICATE-----
MIIBhjCCASugAwIBAgIUaFdNnyjz8QF+JvENb9ojWpDLA+AwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNc2ctcGtjczgtdGVzdDAeFw0yNjA4MTIxNzI0MTBaFw0zNjA4
MDkxNzI0MTBaMBgxFjAUBgNVBAMMDXNnLXBrY3M4LXRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQDYOfJIniTVUt19Gnl56YJBtglZVIjruj+g0Og2sY5dXC6
0FTE2g3R4Yx2voqVNW2vuaoaE9Ti9IBD2qOOu4jho1MwUTAdBgNVHQ4EFgQUNhEz
UVzUxCCMk0GPPO9APOOHEYgwHwYDVR0jBBgwFoAUNhEzUVzUxCCMk0GPPO9APOOH
EYgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAsPPRpuZIi/O/
Z56Tqgjd+5IKSpS7lT3NRgPi41hzaKQCIQDB93gUkFDuWARr62QPzWNYUs8IHWzF
ar3ZlU0rllMZmg==
-----END CERTIFICATE-----
`

const encECAES256SHA256 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCXxRs4ty40lC5BgaY9
JbSeAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQUX+kD2WsvIzNx1rr
Hk7vYgSBkJAPnIoe1Y99xmsYlRmGXwzRlXg42tejfZc5aRCRmEhfMAUH+539kCHL
6FOV+XfrzK+EruzuWruy5qFoj2Sgj2vRIGEW9CRVsXXIoMPNT7F8g6s/ZzqIgS6v
JSai4Cx8WhVitDxfjUot0y9ZSyNMN0Vq2b3G4SUzr9DxhvXXrpBqq3i3hi3xvgb1
FnE/y8AcVQ==
-----END ENCRYPTED PRIVATE KEY-----
`

const encECAES128SHA1 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHmMFEGCSqGSIb3DQEFDTBEMCMGCSqGSIb3DQEFDDAWBBCRIVdsro6Hkq0NPkkG
hyk5AgIIADAdBglghkgBZQMEAQIEEORyTxyuFsPcQYrKdqmhitsEgZCVuiVqZyBM
KyTLA3fHU8Me5zkyPiDtBnhrUsqOMDIp/jjESuSrZY5oNJf6kfuLCumklilj5W9f
qciT+IkGUNVn+D48PeKzrW/+ORN+zUHLIf+LcAE1vaHxV6hB+JcdXex93D6GZ0+6
nq5Z9UbpFQIAPy00CA8JUlni2CNJJda5IqF78TDzTbm7sJykn0ZpYHs=
-----END ENCRYPTED PRIVATE KEY-----
`

const encECAES192 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBFpZHIUGYj6JxaZD6v
0wxNAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBFgQQzMvR8ciwb0YAZa69
bfNJFASBkNntfJX5vRNDgyQWqySxzcgb9P8r4L1+VhYTWoV3wWUyCDaEQNnJV9Dx
m7kcZzNMd2pvokDO9ezZs3byO1F/XbIRv2FqBzF+sG1OPeO0IcifGrnREOR3ThzS
7OHvP8n7yHDPky9e+gscNb9AOXlbC3Ub4cLU1J7uFtRPWVU77eqpW7MZRfo+HGHZ
JXLjlQKGfg==
-----END ENCRYPTED PRIVATE KEY-----
`

const encECAES256SHA512 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDaGbX9WgTLio06AEvZ
hXIzAgIIADAMBggqhkiG9w0CCwUAMB0GCWCGSAFlAwQBKgQQptzkiUvjdjwHaCmV
iutHegSBkO31uoV3JddXSen1G13pjbTTAKJ5xymLx40yiX9xgOABkmOqESki86Xu
nT/S+jW9OG/P/6vzpRFMHMrnXAl7ttR/OWMtIybeQ2qBtTBTYWOszsHZCI3j+B9L
GhsS+O0/TPyr8y3DXzpiIylqMMU06LyqGCI9oGq0YetOmQWUyImZKeT86aSEHTBm
mBEOisS6EQ==
-----END ENCRYPTED PRIVATE KEY-----
`

const encECDES3 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHrMFYGCSqGSIb3DQEFDTBJMDEGCSqGSIb3DQEFDDAkBBDoh8oT1sTg/MykCsv2
YYc7AgIIADAMBggqhkiG9w0CCQUAMBQGCCqGSIb3DQMHBAhwejOI8jOsLASBkLTv
fB28wtAObrg9dsKETvwZjxgCMUnqp/VKFgJQi8sImVbGZdaAnAtwgWryt8w/NUp9
IOvoZZQXt838hosafY0GDe5p7c0ZlyppktUXE5QcyFvTVwbQtHJpNsaVHdLszpgx
cVh0+IL6UiGMNFKy3Bh6Jb6kkqUq6wdoR1hroBpg05PFzfMX45TSWgT+55kdUw==
-----END ENCRYPTED PRIVATE KEY-----
`

const encECScrypt = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSsGAQQB2kcECzAcBBBB3rO121/87vKnLySm
cCivAgJAAAIBCAIBATAdBglghkgBZQMEASoEEFM+HoW/Tgro3YGayGZsF3wEgZAE
O8iBTtyufFR7RiXh4AWI3FGQ4ydIzHIkqJrMXZp/qJl3ZaFrDH4Hji/aIaVfUMIS
RgmGPiO6q1bcORdyP3MsS1PtlVPe3rOx+yzEoNuXldBazQ9Ma4A4KFsNpp/rqY1l
lItAAaqVIxZwW2Mhrqv6yL+eRNAq1lxDBDaeAR4yNfuLdtK+LrJTsTfKrTsNEwc=
-----END ENCRYPTED PRIVATE KEY-----
`

const encRSAAES256 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQosAfWpk62dtsHu91
kzzIyQICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEPBNdUztdZBbusfW
QGl00owEggTQBseO4hrO0bsnJyCp5NcySOxt+51ChEgATacHL8/g/L1pMoJskQsd
xh+xjOLtpA4PI2AxXPlewuXPUNnkUkMTrVwkBbAVki/AIRclCaDhjQ8b+pwFwe2I
zNvxDhgr+eqzvcEbP0vLww4Phv4zwmInHCiaukUotfTwALfPCGukhz/GMQ/SYw4c
r4XjIe9FVDAI7gpNE+Shry1LoGoHsfRsLYc8buvmNwsCl5xHt2+4WheGgwaBeOO0
b2YWVxqra7dza5seLmmcXW+AeayB4BzpHzpK+K/ycxT4c10cLbfla7WUjE4H+jFO
mMP/ou94T3iDpxPM+aTyMyOr6Q/2wUXkiJCErLCdUiYuR2kbAQR36w1VjUeF4/Vh
1HyZ/P0Vj27UAt7gldZ6Y01raP1VPas8U40gn1TfeoENoQY2y799a6FYZdN8zIk9
fe6gmyUDGSgDQN6zFatgtqdKtYSCpIf5TtMzrM1aisyEXWzBg5XGLlU7/Uqze65t
lcqYnaKlFTpQS0O9XGqzm+iboZuQVGlV869P5Hve69cs3lFBlpzcMQUjetHptVBW
d19hNLXc4z0ngwpZ94PDHLMm7rJrwrqOqkorXM3Y/XsDwZMTxRFi2ZEx5S+k9sIc
0jZvWRDHFK/0a/2vI+Ufeefc/JEjksdW5dZGfDRlY76otJHyBQEkofIxOL0/Bp8o
0WdsUu6hJTpTaIjwNvo5iM8vh4rbjV851cFYz57NFI94awxcNkMhTx8kzDM8yYXU
2kVWS6GELEsIGc6pW5OLXppZwyDQstmRt/n3A4lsSl2JTB2vlaK6yEhU33Qg68Dv
21cEREdianOULUxucEZqO3/IZcMZNWlAPMNeHTB3YPsRtByn8aixMNI1N7z90LYo
sZc9LsAHDAPnkK48bBQ95zmU16z5cJQJT9gbNw3NTpizcfsdUD9NDIDwhu1lS3p0
Pfy9/tIN5UJSgcnTwO3HxVeHi26BEb+kVbbJVxfJz40ecPchvvetc/tHfFD+RV7v
sYUrAkDqVc0JwAOHfl86PmgkdOK4cVsId7hHWdjFoWENb/M8SY4LQm3xEgryWW6s
QrWZG1W7pKS00NB3xmA2dxlYO6oY5OEIR4xx+r5mfFdxQKFfHeSEKJ+C2xTk3jXv
moAMM6LFYgfs/E2cdWABzijYwMIyWdnvnRinLr12uMim+bqsNfRA6Q5bNDD34c5V
7ZH4pMOPfEhRvCN9SlvagFxeW4u3hCFJO/eWfUTIam0hdt4HfkIHMWqhtsXIJgHn
9Y0M8/PzOhGoikIBQ9nWNYbRC83nDkzzVfAiz3kKXLFb/qZkKoZqY1/jdjL5t8mx
ZLhfDvLmf23YyDSDLZm9AivuVZ7uDttnWCJNKuys08Zs8uSrk65CcukrTl2YJfMm
G/Q2S5tw4oEKFs2C7J+IzzWmwVbG8OiCeMWQD9ggE4C+1CXPceldm3Upt2SDdHMt
uE4OVaxZLCNfKobYXVZaK65yF7cCfkwSjdeYXOoGm0NhXyNUz94Xo5oBKi2Q+7al
5qErQ/bz4jBheKpmZCwC/yybHgan0reK/uJkqNREclrFuHEG4O8pGJIqZAU0EBXK
y1PPr4oiUOpgdK6BxjvfBK0QIc28GqA0w1KmKEu7aW/5b7uIfVgEYjg=
-----END ENCRYPTED PRIVATE KEY-----
`

const encEDAES256 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDce5SNzGaDl0tR6W2P
S0CiAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ0DXEWiWb9HH3WVTM
shD6swRATDF6gYcBDYw1G/+f0g8oIM3w1C88nAodE+aByAqm0zGYWl2nvwlkup5F
pENApT+36XojKB5q4891/RoFxwH6OQ==
-----END ENCRYPTED PRIVATE KEY-----
`

var encryptedPKCS8Vectors = []struct {
	name  string
	enc   string
	plain string
}{
	{"ec/aes-256-cbc/pbkdf2-hmacsha256", encECAES256SHA256, ecPlainPKCS8},
	{"ec/aes-128-cbc/pbkdf2-hmacsha1", encECAES128SHA1, ecPlainPKCS8},
	{"ec/aes-192-cbc/pbkdf2-default", encECAES192, ecPlainPKCS8},
	{"ec/aes-256-cbc/pbkdf2-hmacsha512", encECAES256SHA512, ecPlainPKCS8},
	{"ec/des-ede3-cbc/pbkdf2", encECDES3, ecPlainPKCS8},
	{"ec/aes-256-cbc/scrypt", encECScrypt, ecPlainPKCS8},
	{"rsa/aes-256-cbc/pbkdf2", encRSAAES256, rsaPlainPKCS8},
	{"ed25519/aes-256-cbc/pbkdf2", encEDAES256, edPlainPKCS8},
}

func decodePEMBytes(t *testing.T, pemStr string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	return block.Bytes
}

func signerFromPKCS8(t *testing.T, der []byte) crypto.Signer {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("parsed key %T is not a crypto.Signer", key)
	}
	return signer
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

func TestDecryptPKCS8Vectors(t *testing.T) {
	for _, v := range encryptedPKCS8Vectors {
		t.Run(v.name, func(t *testing.T) {
			der, err := decryptPKCS8(decodePEMBytes(t, v.enc), []byte(pkcs8TestPassword))
			if err != nil {
				t.Fatalf("decryptPKCS8: %v", err)
			}
			got := signerFromPKCS8(t, der)
			want := signerFromPKCS8(t, decodePEMBytes(t, v.plain))
			if !publicKeysEqual(got.Public(), want.Public()) {
				t.Fatal("decrypted key does not match the reference key")
			}
		})
	}
}

func TestDecryptPKCS8WrongPassword(t *testing.T) {
	_, err := decryptPKCS8(decodePEMBytes(t, encECAES256SHA256), []byte("not-the-password"))
	if !errors.Is(err, errDecryptEncryptedKey) {
		t.Fatalf("err = %v, want errDecryptEncryptedKey", err)
	}
}

func TestDecodeKeyBlockEncryptedPKCS8(t *testing.T) {
	block, _ := pem.Decode([]byte(encRSAAES256))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	t.Run("no password", func(t *testing.T) {
		if _, err := decodeKeyBlock(block, Secret{}); !errors.Is(err, errEncryptedKeyNoPassword) {
			t.Fatalf("err = %v, want errEncryptedKeyNoPassword", err)
		}
	})
	t.Run("with password", func(t *testing.T) {
		der, err := decodeKeyBlock(block, NewSecretString(pkcs8TestPassword))
		if err != nil {
			t.Fatalf("decodeKeyBlock: %v", err)
		}
		if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
			t.Fatalf("ParsePKCS8PrivateKey: %v", err)
		}
	})
}

func TestParseClientCertificateEncryptedKey(t *testing.T) {
	cert, err := parseClientCertificate([]byte(ecCertPEM), NewSecretString(pkcs8TestPassword), []byte(encECAES256SHA256))
	if err != nil {
		t.Fatalf("parseClientCertificate: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("cert.Leaf is nil")
	}
}
