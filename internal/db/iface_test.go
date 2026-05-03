package db

import (
	"github.com/zcp/management-plane/internal/features"
	"github.com/zcp/management-plane/internal/policy"
	"github.com/zcp/management-plane/internal/profiles"
)

// Compile-time checks that DB stores satisfy the store interfaces.
var _ features.FeatureStore = (*FeatureStore)(nil)
var _ profiles.ProfileStore = (*ProfileStore)(nil)
var _ policy.PolicyStore = (*PolicyStore)(nil)
