// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package lockingencryptionregistry_test

import (
	"testing"

	"github.com/opentofu/opentofu/internal/encryption/registry"
	"github.com/opentofu/opentofu/internal/encryption/registry/lockingencryptionregistry"
)

func TestCompliance(t *testing.T) {
	registry.ComplianceTest(t, lockingencryptionregistry.New)
}
