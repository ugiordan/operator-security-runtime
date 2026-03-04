// Package rbacscope provides dynamic RBAC scoping for Kubernetes operators.
//
// RBACScoper creates and manages namespace-scoped Roles and RoleBindings so that
// an operator ServiceAccount can access resources only in namespaces where a
// Custom Resource exists. When the CR is deleted, the scoped access is revoked.
//
// This replaces static cluster-wide resource access (via ClusterRole) with
// namespace-scoped grants tied to CR lifecycle, following the principle of least
// privilege. AllowedRules accepts any []rbacv1.PolicyRule, supporting
// arbitrary combinations of API groups, resources, and verbs.
//
// For operators whose static RBAC (via ClusterRole) already sufficiently constrains
// access, AllowAllRules can be used as an explicit escape hatch that bypasses the
// ceiling enforcement. This allows RBACScoper to manage the namespace-scoped Role
// and RoleBinding lifecycle without enforcing a specific permission set.
//
// Usage:
//
//	allowed, err := rbacscope.NewAllowedRules(rbacv1.PolicyRule{
//	    APIGroups: []string{""},
//	    Resources: []string{"secrets"},
//	    Verbs:     []string{"get", "list", "watch"},
//	})
//	if err != nil { ... }
//
//	scoper, err := rbacscope.NewRBACScoper(
//	    mgr.GetClient(),
//	    mgr.GetScheme(),
//	    rbacscope.OperatorIdentity{
//	        Name:           "my-operator",
//	        ServiceAccount: "my-operator-controller-manager",
//	        Namespace:      "my-operator-system",
//	    },
//	    allowed,
//	)
//	if err != nil { ... }
//
//	// In your reconciler:
//	if err := scoper.EnsureAccess(ctx, cr); err != nil { ... }
//
//	// During CR deletion (in finalizer):
//	if err := scoper.CleanupAccess(ctx, cr); err != nil { ... }
package rbacscope
