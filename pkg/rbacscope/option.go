package rbacscope

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

// Option configures an RBACScoper or ClusterRBACScoper.
type Option interface {
	apply(s *scopeConfig) // unexported - prevents external implementations
}

type optionFunc func(s *scopeConfig)

func (f optionFunc) apply(s *scopeConfig) { f(s) }

// scopeConfig holds optional configuration for an RBACScoper.
type scopeConfig struct {
	scheme                   *runtime.Scheme
	deniedNamespaces         []string
	deniedNamespacesModified bool    // set by WithDeniedNamespaces/WithAdditionalDeniedNamespaces
	errs                     []error // deferred validation errors from options
}

func defaultScopeConfig() scopeConfig {
	return scopeConfig{
		deniedNamespaces: []string{
			"kube-system", "kube-public", "kube-node-lease", "default",
			"openshift-", // prefix match: any namespace starting with "openshift-"
		},
	}
}

// WithDeniedNamespaces replaces the default denied-namespace list.
// At least one namespace must be provided; use this only when the defaults
// are inappropriate for your environment.
// This option only applies to RBACScoper (namespace-scoped grants);
// it has no effect on ClusterRBACScoper which manages cluster-scoped resources.
// WARNING: This removes built-in protections for kube-system, kube-public, etc.
// Use WithAdditionalDeniedNamespaces to add namespaces without removing defaults.
// Namespace entries ending with "-" are treated as prefix patterns
// (e.g., "openshift-" matches all namespaces starting with "openshift-").
//
// Ordering note: if combined with WithAdditionalDeniedNamespaces, place
// WithDeniedNamespaces first. WithDeniedNamespaces replaces the entire list,
// so a later WithDeniedNamespaces discards any previously appended entries.
func WithDeniedNamespaces(first string, rest ...string) Option {
	return optionFunc(func(s *scopeConfig) {
		s.deniedNamespaces = append([]string{first}, rest...)
		s.deniedNamespacesModified = true
	})
}

// WithAdditionalDeniedNamespaces appends to the denied-namespace list without
// removing the defaults. At least one namespace must be provided.
// This option only applies to RBACScoper (namespace-scoped grants);
// it has no effect on ClusterRBACScoper which manages cluster-scoped resources.
func WithAdditionalDeniedNamespaces(namespaces ...string) Option {
	return optionFunc(func(s *scopeConfig) {
		if len(namespaces) == 0 {
			s.errs = append(s.errs, fmt.Errorf("WithAdditionalDeniedNamespaces requires at least one namespace"))
			return
		}
		s.deniedNamespaces = append(s.deniedNamespaces, namespaces...)
		s.deniedNamespacesModified = true
	})
}

// WithScheme enables OwnerReference-based ownership for ClusterRBACScoper
// when the owner is cluster-scoped (cluster-scoped owner → cluster-scoped
// ClusterRole/ClusterRoleBinding). Without this option, ClusterRBACScoper
// uses annotation-based ownership for all owners.
//
// The scheme is required because controllerutil.SetOwnerReference needs it
// to look up the owner's GVK. When both the owner and owned resource are
// cluster-scoped, Kubernetes allows native OwnerReferences, providing
// automatic garbage collection and API-server-validated ownership.
//
// This option has no effect on RBACScoper (which manages namespace-scoped
// resources where cluster-scoped owners cannot use OwnerReferences).
func WithScheme(scheme *runtime.Scheme) Option {
	return optionFunc(func(s *scopeConfig) {
		if scheme == nil {
			s.errs = append(s.errs, fmt.Errorf("WithScheme requires a non-nil scheme"))
			return
		}
		s.scheme = scheme
	})
}
