// Package rbacscope provides dynamic RBAC scoping for Kubernetes operators.
//
// RBACScoper creates and manages namespace-scoped Roles and RoleBindings so that
// an operator ServiceAccount can access resources only in namespaces where a
// Custom Resource exists. When the CR is deleted, the scoped access is revoked.
// Same-namespace grants use OwnerReferences; cross-namespace grants (via
// EnsureAccessInNamespace) use annotation-based ownership.
//
// ClusterRBACScoper provides the same lifecycle management for cluster-scoped
// ClusterRoles and ClusterRoleBindings, using annotation-based ownership since
// OwnerReferences cannot cross namespace boundaries to cluster scope.
//
// Both scopers support any combination of API groups, resources, and verbs via
// AllowedRules, which accepts Kubernetes-native rbacv1.PolicyRule structs.
// For operators whose static RBAC (via ClusterRole) already sufficiently constrains
// access, AllowAllRules can be used as an explicit escape hatch that bypasses the
// ceiling enforcement.
//
// Namespace-scoped usage:
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
//	// Same-namespace access:
//	if err := scoper.EnsureAccess(ctx, cr); err != nil { ... }
//	if err := scoper.CleanupAccess(ctx, cr); err != nil { ... }
//
//	// Cross-namespace access:
//	if err := scoper.EnsureAccessInNamespace(ctx, cr, targetNS); err != nil { ... }
//	if err := scoper.CleanupAllAccess(ctx, cr); err != nil { ... }
//
// Cluster-scoped usage:
//
//	clusterScoper, err := rbacscope.NewClusterRBACScoper(
//	    mgr.GetClient(),
//	    rbacscope.OperatorIdentity{
//	        Name:           "my-operator",
//	        ServiceAccount: "my-operator-controller-manager",
//	        Namespace:      "my-operator-system",
//	    },
//	    allowed,
//	)
//	if err != nil { ... }
//
//	if err := clusterScoper.EnsureAccess(ctx, cr); err != nil { ... }
//	if err := clusterScoper.CleanupAccess(ctx, cr); err != nil { ... }
package rbacscope
