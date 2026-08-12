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

// This file is a small, self-contained decryptor for encrypted PKCS#8 private
// keys ("BEGIN ENCRYPTED PRIVATE KEY"), the format modern OpenSSL produces by
// default for password-protected keys. The Go standard library parses only
// unencrypted PKCS#8, and golang.org/x/crypto exposes the key-derivation
// primitives (PBKDF2, scrypt) but no end-to-end decryptor, so this file wires
// the standard pieces together for the PBES2 schemes seen in practice.
//
// It is deliberately isolated here so it can be replaced wholesale if the
// standard library or x/crypto ever grows a first-class equivalent. It decrypts
// a standard, well-specified format (RFC 5958 / RFC 8018) using vetted
// primitives; it does not implement any novel cryptography.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // 3DES (des-ede3-cbc) is a legacy PBES2 cipher we must read to decrypt older keys; it is never used to encrypt.
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the default and still-common PBKDF2 PRF for PKCS#8 keys; it is used only for key derivation of existing keys, not for signing.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// errUnsupportedEncryptedKey is returned when an encrypted PKCS#8 key uses a
// key-derivation function or cipher this decryptor does not implement. The
// message points the caller at converting the key with OpenSSL.
var errUnsupportedEncryptedKey = errors.New("safeguard: unsupported encrypted PKCS#8 key (only PBES2 with PBKDF2/scrypt and AES-CBC or 3DES-CBC is supported); re-encrypt with `openssl pkcs8 -topk8 -v2 aes-256-cbc` or supply an unencrypted PEM key")

// errDecryptEncryptedKey is returned when decryption fails, which almost always
// means the supplied password was incorrect.
var errDecryptEncryptedKey = errors.New("safeguard: could not decrypt encrypted PKCS#8 private key (incorrect password?)")

// Object identifiers for the PBES2 scheme, its key-derivation functions, PRFs,
// and ciphers (RFC 8018, RFC 8103, RFC 7914).
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// encryptedPrivateKeyInfo is the ASN.1 structure of an EncryptedPrivateKeyInfo
// (RFC 5958): an encryption algorithm identifier and the ciphertext.
type encryptedPrivateKeyInfo struct {
	Algo          pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// pbes2Params holds the PBES2 parameters: a key-derivation function and an
// encryption scheme (RFC 8018 A.4).
type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

// pbkdf2Params holds the PBKDF2 parameters (RFC 8018 A.2). Salt is modeled as an
// OCTET STRING (the specified-salt form used in practice); the optional
// keyLength and PRF default appropriately when absent.
type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

// scryptParams holds the scrypt parameters (RFC 7914).
type scryptParams struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
	KeyLength                int `asn1:"optional"`
}

// decryptPKCS8 decrypts an encrypted PKCS#8 private key (the DER bytes of an
// EncryptedPrivateKeyInfo) with password and returns the inner, unencrypted
// PKCS#8 DER, ready for x509.ParsePKCS8PrivateKey. Only PBES2 with PBKDF2 or
// scrypt key derivation and AES-CBC or 3DES-CBC encryption is supported.
func decryptPKCS8(der, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("safeguard: parse encrypted private key: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, errUnsupportedEncryptedKey
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("safeguard: parse PBES2 parameters: %w", err)
	}

	block, iv, err := cipherFromScheme(params.EncryptionScheme, params.KeyDerivationFunc, password)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errUnsupportedEncryptedKey
	}
	if len(epki.EncryptedData) == 0 || len(epki.EncryptedData)%block.BlockSize() != 0 {
		return nil, errDecryptEncryptedKey
	}

	plaintext := make([]byte, len(epki.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, epki.EncryptedData)

	unpadded, err := pkcs7Unpad(plaintext, block.BlockSize())
	if err != nil {
		zeroBytes(plaintext)
		return nil, err
	}
	return unpadded, nil
}

// cipherFromScheme derives the symmetric key with the key-derivation function
// and builds the CBC block cipher named by scheme, returning the cipher and its
// IV. The derived key is zeroed before returning; only the constructed cipher
// retains it.
func cipherFromScheme(scheme, kdf pkix.AlgorithmIdentifier, password []byte) (cipher.Block, []byte, error) {
	var keyLen int
	switch {
	case scheme.Algorithm.Equal(oidAES128CBC):
		keyLen = 16
	case scheme.Algorithm.Equal(oidAES192CBC):
		keyLen = 24
	case scheme.Algorithm.Equal(oidAES256CBC):
		keyLen = 32
	case scheme.Algorithm.Equal(oidDESEDE3CBC):
		keyLen = 24
	default:
		return nil, nil, errUnsupportedEncryptedKey
	}

	var iv []byte
	if _, err := asn1.Unmarshal(scheme.Parameters.FullBytes, &iv); err != nil {
		return nil, nil, fmt.Errorf("safeguard: parse cipher IV: %w", err)
	}

	key, err := deriveKey(kdf, password, keyLen)
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(key)

	var block cipher.Block
	if scheme.Algorithm.Equal(oidDESEDE3CBC) {
		block, err = des.NewTripleDESCipher(key) //nolint:gosec // legacy cipher, read-only for decryption of existing keys.
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("safeguard: build cipher: %w", err)
	}
	return block, iv, nil
}

// deriveKey runs the key-derivation function named by kdf against password to
// produce a keyLen-byte symmetric key. keyLen is the cipher's key size and is
// used when the KDF parameters omit an explicit key length.
func deriveKey(kdf pkix.AlgorithmIdentifier, password []byte, keyLen int) ([]byte, error) {
	switch {
	case kdf.Algorithm.Equal(oidPBKDF2):
		var p pbkdf2Params
		if _, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); err != nil {
			return nil, fmt.Errorf("safeguard: parse PBKDF2 parameters: %w", err)
		}
		prf, err := prfHash(p.PRF)
		if err != nil {
			return nil, err
		}
		kl := keyLen
		if p.KeyLength > 0 {
			kl = p.KeyLength
		}
		return pbkdf2.Key(password, p.Salt, p.IterationCount, kl, prf), nil
	case kdf.Algorithm.Equal(oidScrypt):
		var p scryptParams
		if _, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); err != nil {
			return nil, fmt.Errorf("safeguard: parse scrypt parameters: %w", err)
		}
		kl := keyLen
		if p.KeyLength > 0 {
			kl = p.KeyLength
		}
		return scrypt.Key(password, p.Salt, p.CostParameter, p.BlockSize, p.ParallelizationParameter, kl)
	default:
		return nil, errUnsupportedEncryptedKey
	}
}

// prfHash maps a PBKDF2 pseudo-random-function algorithm identifier to its hash
// constructor. An absent PRF defaults to HMAC-SHA1 (RFC 8018).
func prfHash(prf pkix.AlgorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case len(prf.Algorithm) == 0, prf.Algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case prf.Algorithm.Equal(oidHMACWithSHA224):
		return sha256.New224, nil
	case prf.Algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case prf.Algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case prf.Algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	default:
		return nil, errUnsupportedEncryptedKey
	}
}

// pkcs7Unpad removes PKCS#7 padding from a decrypted block. An invalid padding
// almost always means the password was wrong, so it maps to errDecryptEncryptedKey.
// The padding length is compared in constant time to avoid leaking it.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errDecryptEncryptedKey
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, errDecryptEncryptedKey
	}
	pad := data[len(data)-n:]
	expected := make([]byte, n)
	for i := range expected {
		expected[i] = byte(n)
	}
	if !hmac.Equal(pad, expected) {
		return nil, errDecryptEncryptedKey
	}
	return data[:len(data)-n], nil
}
