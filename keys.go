// Copyright 2026 Modgud, Inc.
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

// ParsePrivateKeyPEM parses one PEM-encoded private key for JWTConfig.SigningKey:
// PKCS #8 ("PRIVATE KEY", what openssl genpkey writes), SEC 1 ("EC PRIVATE KEY")
// or PKCS #1 ("RSA PRIVATE KEY"). It refuses encrypted keys and anything after the
// key. New checks the key's type, curve and size.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, err := singlePEMBlock(data)
	if err != nil {
		return nil, err
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("PEM block is not a private key")
	}
	if err != nil {
		return nil, errors.New("private key PEM block is malformed")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return signer, nil
}

// ParsePublicKeyPEM parses one PEM-encoded public key for
// JWTConfig.VerificationKeys: PKIX ("PUBLIC KEY", what openssl pkey -pubout
// writes) or PKCS #1 ("RSA PUBLIC KEY"). New checks the key's type, curve and size.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, err := singlePEMBlock(data)
	if err != nil {
		return nil, err
	}
	var key any
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("PEM block is not a public key")
	}
	if err != nil {
		return nil, errors.New("public key PEM block is malformed")
	}
	return key, nil
}

// singlePEMBlock decodes exactly one unencrypted PEM block. Error messages never
// include the input.
func singlePEMBlock(data []byte) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("PEM data must hold exactly one key")
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, errors.New("encrypted PEM keys are not supported: decrypt the key first")
	}
	return block, nil
}
