// Copyright (c) 2020 Yandex LLC. All rights reserved.

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"

	"github.com/yandex-cloud/kms-clients-go/yckmstink"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

const (
	aad = "This is AAD"
)

// This example shows how to do encryption and decryption directly with Yandex.Cloud KMS client.
// This method supports plaintexts up to 32kb.
func main() {
	token := flag.String("token", "", "Your Yandex.Cloud OAuth token")
	keyID := flag.String("key-id", "", "KMS key id")
	encrypt := flag.String("encrypt", "", "String to encrypt")
	decrypt := flag.String("decrypt", "", "String to decrypt (must be in base64)")

	flag.Parse()
	if *token == "" {
		flag.Usage()
		log.Fatal("token is required")
	}
	if *keyID == "" {
		flag.Usage()
		log.Fatal("key-id is required")
	}

	sdk, err := ycsdk.Build(context.Background(), ycsdk.Config{
		Credentials: ycsdk.OAuthToken(*token),
	})
	if err != nil {
		log.Fatalf("error when creating SDK: %v", err)
	}

	// Unlike the yckmstink.NewYCKMSClient, NewYCAEAD accepts keyIDs.
	a := yckmstink.NewYCAEAD(*keyID, sdk)

	if *encrypt != "" {
		ciphertext, err := a.Encrypt([]byte(*encrypt), []byte(aad))
		if err != nil {
			log.Fatalf("error when encrypting: %v", err)
		}
		log.Printf("Ciphertext (in base64): %s", base64.StdEncoding.EncodeToString(ciphertext))
	}
	if *decrypt != "" {
		ciphertext, err := base64.StdEncoding.DecodeString(*decrypt)
		if err != nil {
			log.Fatalf("ciphertext must be in base64: %v", err)
		}
		plaintext, err := a.Decrypt(ciphertext, []byte(aad))
		if err != nil {
			log.Fatalf("error when encrypting: %v", err)
		}
		log.Printf("Plaintext: %s", string(plaintext))
	}
}
