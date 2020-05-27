// Copyright (c) 2020 Yandex LLC. All rights reserved.

package yckmstink

import (
	"fmt"
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"

	ycsdk "bb.yandex-team.ru/cloud/cloud-go/sdk"
)

const (
	ycKmsPrefix = "yc-kms://"
)

// YCKMSClient represents a client that connects to the YC KMS backend.
type YCKMSClient struct {
	keyURI string
	sdk    *ycsdk.SDK
}

var _ registry.KMSClient = (*YCKMSClient)(nil)

func NewYCKMSClient(URI string, sdk *ycsdk.SDK) (*YCKMSClient, error) {
	err := validateURI(URI)
	if err != nil {
		return nil, err
	}
	return &YCKMSClient{
		keyURI: URI,
		sdk:    sdk,
	}, nil
}

func validateURI(URI string) error {
	if len(URI) > 0 && !strings.HasPrefix(strings.ToLower(URI), ycKmsPrefix) {
		return fmt.Errorf("key URI must start with %s", ycKmsPrefix)
	}
	return nil
}

func (c *YCKMSClient) Supported(keyURI string) bool {
	if (len(c.keyURI) > 0) && (strings.Compare(strings.ToLower(c.keyURI), strings.ToLower(keyURI)) == 0) {
		return true
	}
	return (len(c.keyURI) == 0) && (strings.HasPrefix(strings.ToLower(keyURI), ycKmsPrefix))
}

func (c *YCKMSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	err := c.validateBoundClient(keyURI)
	if err != nil {
		return nil, err
	}
	keyID, err := validateTrimKMSPrefix(keyURI, ycKmsPrefix)
	if err != nil {
		return nil, err
	}
	return NewYCAEAD(keyID, c.sdk), nil
}

func (c *YCKMSClient) validateBoundClient(keyURI string) error {
	if len(c.keyURI) > 0 && strings.Compare(strings.ToLower(c.keyURI), strings.ToLower(keyURI)) != 0 {
		return fmt.Errorf("this client is bound to key %s, cannot load keys bound to key %s", c.keyURI, keyURI)
	}
	return nil
}

func validateKMSPrefix(keyURI, prefix string) bool {
	if len(keyURI) > 0 && strings.HasPrefix(strings.ToLower(keyURI), prefix) {
		return true
	}
	return false
}

func validateTrimKMSPrefix(keyURI, prefix string) (string, error) {
	if !validateKMSPrefix(keyURI, prefix) {
		return "", fmt.Errorf("key URI must start with %s", prefix)
	}
	return strings.TrimPrefix(keyURI, prefix), nil
}
