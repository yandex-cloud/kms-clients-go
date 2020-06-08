// Copyright (c) 2020 Yandex LLC. All rights reserved.

// Package yckmstink provides integration with the Yandex.Cloud KMS.
package yckmstink

import (
	"context"

	"github.com/google/tink/go/tink"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

// YCAEAD represents a encrypt/decrypt service using particular keyID
type YCAEAD struct {
	keyID string
	sdk   *ycsdk.SDK
}

var _ tink.AEAD = (*YCAEAD)(nil)

// NewYCAEAD returns a new AEAD instance backed by keyID.
func NewYCAEAD(keyID string, sdk *ycsdk.SDK) *YCAEAD {
	return &YCAEAD{
		keyID: keyID,
		sdk:   sdk,
	}
}

// Encrypt AEAD encrypts the plaintext data and uses addtional data from authentication.
func (aead *YCAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	resp, err := aead.sdk.KMSCrypto().SymmetricCrypto().Encrypt(context.Background(), &kms.SymmetricEncryptRequest{
		KeyId:      aead.keyID,
		AadContext: additionalData,
		Plaintext:  plaintext,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

// Decrypt AEAD decrypts the data and verified the additional data.
func (aead *YCAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	resp, err := aead.sdk.KMSCrypto().SymmetricCrypto().Decrypt(context.Background(), &kms.SymmetricDecryptRequest{
		KeyId:      aead.keyID,
		AadContext: additionalData,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
