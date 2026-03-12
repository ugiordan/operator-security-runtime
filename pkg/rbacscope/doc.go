// Package rbacscope provides dynamic RBAC scoping for Kubernetes operators.
//
// RBACScoper creates and manages namespace-scoped Roles and RoleBindings so that
// an operator ServiceAccount can access resources only in namespaces where a
// Custom Resource exists. When the CR is deleted, the scoped access is revoked.
// Same-namespace grants use OwnerReferences; cross-namespace grants (via
// EnsureAccessInNamespace) use annotation-based ownership.
//
// ClusterRBACScoper provides the same lifecycle management for cluster-scoped
// ClusterRoles and ClusterRoleBindings. It accepts both namespace-scoped and
// cluster-scoped owners. When constructed with WithScheme and the owner is
// cluster-scoped, OwnerReferences are used (native K8s GC). For namespace-scoped
// owners (or without WithScheme), annotation-based ownership is used since
// Kubernetes rejects OwnerReferences from namespace-scoped to cluster-scoped.
//
// Both scopers support any combination of API groups, resources, and verbs via
// AllowedRules, which accepts Kubernetes-native rbacv1.PolicyRule structs.
// For operators whose static RBAC (via ClusterRole) already sufficiently constrains
// access, DeferToStaticRBAC can be used as an explicit escape hatch that bypasses the
// ceiling enforcement.
//
// CleanupAccessInNamespace provides targeted cross-namespace cleanup for a single
// namespace, complementing CleanupAllAccess which operates across all namespaces.
//
// GarbageCollectOrphanedOwners scans managed resources and removes stale annotation
// entries for owners that no longer exist. It accepts an OwnerResolver callback
// and returns a GCResult with scan statistics.
//
// Both scopers satisfy the AccessScoper interface, which provides EnsureAccess,
// CleanupAccess, and GarbageCollectOrphanedOwners. This enables generic middleware,
// wrappers, and testing mocks that work with either scoper type.
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
// Cluster-scoped usage (with OwnerReferences for cluster-scoped owners):
//
//	clusterScoper, err := rbacscope.NewClusterRBACScoper(
//	    mgr.GetClient(),
//	    rbacscope.OperatorIdentity{
//	        Name:           "my-operator",
//	        ServiceAccount: "my-operator-controller-manager",
//	        Namespace:      "my-operator-system",
//	    },
//	    allowed,
//	    rbacscope.WithScheme(mgr.GetScheme()), // enables OwnerReferences for cluster-scoped owners
//	)
//	if err != nil { ... }
//
//	// Works with both namespace-scoped and cluster-scoped owners:
//	if err := clusterScoper.EnsureAccess(ctx, cr); err != nil { ... }
//	if err := clusterScoper.CleanupAccess(ctx, cr); err != nil { ... }
package rbacscope
