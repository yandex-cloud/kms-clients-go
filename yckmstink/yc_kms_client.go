// Copyright (c) 2020 Yandex LLC. All rights reserved.

// Package yckmstink provides integration with the Yandex.Cloud KMS.
package yckmstink

import (
	"fmt"
	"strings"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"

	ycsdk "github.com/yandex-cloud/go-sdk"
)

const (
	YCKMSPrefix = "yc-kms://"
)

// YCKMSClient represents a client that connects to the Yandex.Cloud KMS backend.
type YCKMSClient struct {
	keyURI string
	sdk    *ycsdk.SDK
}

var _ registry.KMSClient = (*YCKMSClient)(nil)

// NewYCKMSClient returns a new client to Yandex.Cloud KMS. If keyURI is not empty, the client is bound to the URI.
func NewYCKMSClient(keyURI string, sdk *ycsdk.SDK) (*YCKMSClient, error) {
	err := validateURI(keyURI)
	if err != nil {
		return nil, err
	}
	return &YCKMSClient{
		keyURI: keyURI,
		sdk:    sdk,
	}, nil
}

func validateURI(URI string) error {
	if len(URI) > 0 && !strings.HasPrefix(strings.ToLower(URI), YCKMSPrefix) {
		return fmt.Errorf("key URI must start with %s", YCKMSPrefix)
	}
	return nil
}

// Supported returns true if this client does support keyURI
func (c *YCKMSClient) Supported(keyURI string) bool {
	if (len(c.keyURI) > 0) && (strings.Compare(strings.ToLower(c.keyURI), strings.ToLower(keyURI)) == 0) {
		return true
	}
	return (len(c.keyURI) == 0) && (strings.HasPrefix(strings.ToLower(keyURI), YCKMSPrefix))
}

// GetAEAD gets a new AEAD instance backed by keyURI.
func (c *YCKMSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	err := c.validateBoundClient(keyURI)
	if err != nil {
		return nil, err
	}
	keyID, err := validateTrimKMSPrefix(keyURI, YCKMSPrefix)
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
