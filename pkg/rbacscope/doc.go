// Package rbacscope provides dynamic RBAC scoping for Kubernetes operators.
//
// RBACScoper creates and manages namespace-scoped Roles and RoleBindings so that
// an operator ServiceAccount can access resources only in namespaces where a
// Custom Resource exists. When the CR is deleted, the scoped access is revoked.
//
// This replaces static cluster-wide resource access (via ClusterRole) with
// namespace-scoped grants tied to CR lifecycle, following the principle of least
// privilege. The Rules field accepts any []rbacv1.PolicyRule, supporting
// arbitrary combinations of API groups, resources, and verbs.
//
// Usage:
//
//	scoper := &rbacscope.RBACScoper{
//	    Client:              mgr.GetClient(),
//	    Scheme:              mgr.GetScheme(),
//	    OperatorName:        "my-operator",
//	    OperatorSAName:      "my-operator-controller-manager",
//	    OperatorSANamespace: "my-operator-system",
//	    Rules: []rbacv1.PolicyRule{{
//	        APIGroups: []string{""},
//	        Resources: []string{"secrets"},
//	        Verbs:     []string{"get", "list", "watch"},
//	    }},
//	}
//
//	// In your reconciler:
//	if err := scoper.EnsureAccess(ctx, cr); err != nil { ... }
//
//	// During CR deletion (in finalizer):
//	if err := scoper.CleanupAccess(ctx, cr); err != nil { ... }
package rbacscope
