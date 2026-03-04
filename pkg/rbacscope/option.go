package rbacscope

// Option configures an RBACScoper.
type Option interface {
	apply(s *scopeConfig) // unexported - prevents external implementations
}

type optionFunc func(s *scopeConfig)

func (f optionFunc) apply(s *scopeConfig) { f(s) }

// scopeConfig holds optional configuration for an RBACScoper.
type scopeConfig struct {
	deniedNamespaces         []string
	deniedNamespacesModified bool // set by WithDeniedNamespaces/WithAdditionalDeniedNamespaces
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
// removing the defaults.
// This option only applies to RBACScoper (namespace-scoped grants);
// it has no effect on ClusterRBACScoper which manages cluster-scoped resources.
func WithAdditionalDeniedNamespaces(namespaces ...string) Option {
	return optionFunc(func(s *scopeConfig) {
		s.deniedNamespaces = append(s.deniedNamespaces, namespaces...)
		s.deniedNamespacesModified = true
	})
}
