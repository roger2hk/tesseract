// Copyright 2024 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tink

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type Signer struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	tinkSigner tink.Signer
}

// Public returns the public key stored in the Signer object.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the data with the tink signer.
// Only crypto.SHA256 is supported.
func (s *Signer) Sign(_ io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Verify hash function.
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash func: %v", opts.HashFunc())
	}

	return s.tinkSigner.Sign(data)
}

// NewSigner creates a signer that uses the key encrypted in KMS envelope encryption
// with Tink to sign digest.
func NewSigner(ctx context.Context, kekURI string) (*Signer, error) {
	kek, err := getKeyEncryptionKey(ctx, kekURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get key encryption key: %w", err)
	}

	// Retrieve the Signer primitive from privateKeysetHandle.
	signer, err := signature.NewSigner(privateKeysetHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Signer{
		tinkSigner: signer,
	}, nil
}

// getKeyEncryptionKey returns a Tink AEAD encryption key from KMS.
// Only GCP KMS is supported at the moment.
func getKeyEncryptionKey(ctx context.Context, kmsKey string) (tink.AEAD, error) {
	switch {
	case strings.HasPrefix(kmsKey, "gcp-kms://"):
		gcpKMSClient, err := gcpkms.NewClientWithOptions(ctx, kmsKey)
		if err != nil {
			return nil, err
		}
		registry.RegisterKMSClient(gcpKMSClient)
		return gcpKMSClient.GetAEAD(kmsKey)
	default:
		return nil, errors.New("unsupported KMS key type")
	}
}
