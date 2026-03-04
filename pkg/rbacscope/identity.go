package rbacscope

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// OperatorIdentity identifies the operator whose ServiceAccount will
// receive scoped RBAC access.
type OperatorIdentity struct {
	Name           string // Operator name, used in Role/RoleBinding naming
	ServiceAccount string // Operator's ServiceAccount name
	Namespace      string // Operator's ServiceAccount namespace
}

// AllowedRules holds the set of PolicyRules that the RBACScoper is
// allowed to grant. Use NewAllowedRules to create an instance with
// explicit rules, or DeferToStaticRBAC to bypass ceiling enforcement.
type AllowedRules struct {
	rules    []rbacv1.PolicyRule
	allowAll bool
}

// NewAllowedRules creates an AllowedRules from one or more PolicyRules.
// It returns an error if no rules are provided.
func NewAllowedRules(rules ...rbacv1.PolicyRule) (AllowedRules, error) {
	if len(rules) == 0 {
		return AllowedRules{}, fmt.Errorf("AllowedRules must contain at least one PolicyRule")
	}
	deepCopy := make([]rbacv1.PolicyRule, len(rules))
	for i := range rules {
		deepCopy[i] = *rules[i].DeepCopy()
	}
	return AllowedRules{rules: deepCopy}, nil
}

// DeferToStaticRBAC returns an AllowedRules that bypasses ceiling enforcement.
// The scoper will still create Roles/ClusterRoles (for lifecycle tracking and
// cleanup), but they will contain zero rules — granting no additional
// permissions. Use this when the operator's static ClusterRole already
// constrains access appropriately and dynamic rule scoping is not needed.
func DeferToStaticRBAC() AllowedRules {
	return AllowedRules{allowAll: true}
}

// AccessScoper is the common interface satisfied by both RBACScoper and
// ClusterRBACScoper. It enables generic wrappers, middleware, and testing
// mocks that work with either scoper type.
//
// RBACScoper manages namespace-scoped Roles/RoleBindings.
// ClusterRBACScoper manages cluster-scoped ClusterRoles/ClusterRoleBindings.
// Both follow the same ensure/cleanup lifecycle pattern.
type AccessScoper interface {
	// EnsureAccess creates or updates scoped RBAC resources for the given
	// owner. The owner must be namespace-scoped.
	EnsureAccess(ctx context.Context, owner client.Object) error

	// CleanupAccess removes the owner from scoped RBAC resources.
	// Deletes resources if no owners remain.
	CleanupAccess(ctx context.Context, owner client.Object) error

	// GarbageCollectOrphanedOwners scans managed resources and removes
	// stale annotation entries for owners that no longer exist.
	GarbageCollectOrphanedOwners(ctx context.Context, resolver OwnerResolver) (GCResult, error)
}

// Compile-time interface satisfaction checks.
var (
	_ AccessScoper = (*RBACScoper)(nil)
	_ AccessScoper = (*ClusterRBACScoper)(nil)
)
