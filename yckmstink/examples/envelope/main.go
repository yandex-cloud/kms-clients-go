// Copyright (c) 2020 Yandex LLC. All rights reserved.

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"

	"github.com/yandex-cloud/kms-clients-go/yckmstink"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/google/tink/go/aead"
)

const (
	aad = "This is AAD"
)

// This example shows how to do envelope encryption with Yandex.Cloud KMS client.
// This method supports plaintexts of arbitrary length.
func main() {
	token := flag.String("token", "", "Your Yandex.Cloud OAuth token")
	keyID := flag.String("key-id", "", "KMS key id")
	encrypt := flag.String("encrypt", "", "String to encrypt")
	decrypt := flag.String("decrypt", "", "String to decrypt")

	flag.Parse()
	if *token == "" {
		flag.Usage()
		log.Fatal("token is required")
	}
	if *keyID == "" {
		flag.Usage()
		log.Fatal("key-id is required for encryption")
	}

	sdk, err := ycsdk.Build(context.Background(), ycsdk.Config{
		Credentials: ycsdk.OAuthToken(*token),
	})
	if err != nil {
		log.Fatalf("error when creating SDK: %v", err)
	}

	remoteAead := yckmstink.NewYCAEAD(*keyID, sdk)

	dekTemplate := aead.AES256GCMKeyTemplate()
	a := aead.NewKMSEnvelopeAEAD(*dekTemplate, remoteAead)

	if *encrypt != "" {
		// Create a new AES-256 key (dek) and encrypt it with keyID in KMS, then encrypt plaintext with dek.
		ciphertext, err := a.Encrypt([]byte(*encrypt), []byte(aad))
		if err != nil {
			log.Fatalf("error when encrypting: %v", err)
		}

		// Ciphertext contains both the encrypted dek and ciphertext.
		log.Printf("Ciphertext (in base64): %s", base64.StdEncoding.EncodeToString(ciphertext))
	}
	if *decrypt != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(*decrypt)
		if err != nil {
			log.Fatalf("ciphertext must be in base64: %v", err)
		}

		// Get encrypted dek from ciphertext, decrypt it via KMS and then decrypt the remaining ciphertext.
		plaintext, err := a.Decrypt(ciphertext, []byte(aad))
		if err != nil {
			log.Fatalf("error when encrypting: %v", err)
		}
		log.Printf("Plaintext: %s", string(plaintext))
	}
}
