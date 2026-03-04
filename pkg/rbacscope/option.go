package rbacscope

// Option configures an RBACScoper.
type Option interface {
	apply(s *scopeConfig) // unexported - prevents external implementations
}

type optionFunc func(s *scopeConfig)

func (f optionFunc) apply(s *scopeConfig) { f(s) }

// scopeConfig holds optional configuration for an RBACScoper.
type scopeConfig struct {
	deniedNamespaces      []string
	aggregationLabelCheck bool
}

func defaultScopeConfig() scopeConfig {
	return scopeConfig{
		deniedNamespaces: []string{
			"kube-system", "kube-public", "kube-node-lease", "default",
			"openshift-", // prefix match: any namespace starting with "openshift-"
		},
		aggregationLabelCheck: false,
	}
}

// WithDeniedNamespaces replaces the entire denied namespace list.
// WARNING: This removes built-in protections for kube-system, kube-public, etc.
// Use WithAdditionalDeniedNamespaces to add namespaces without removing defaults.
// Namespace entries ending with "-" are treated as prefix patterns
// (e.g., "openshift-" matches all namespaces starting with "openshift-").
func WithDeniedNamespaces(namespaces ...string) Option {
	return optionFunc(func(s *scopeConfig) {
		s.deniedNamespaces = namespaces
	})
}

// WithAdditionalDeniedNamespaces appends namespaces to the default denied list
// without removing built-in protections for kube-system, kube-public, etc.
func WithAdditionalDeniedNamespaces(namespaces ...string) Option {
	return optionFunc(func(s *scopeConfig) {
		s.deniedNamespaces = append(s.deniedNamespaces, namespaces...)
	})
}

// WithAggregationLabelCheck enables or disables the aggregation label
// check on ClusterRoles.
func WithAggregationLabelCheck(enabled bool) Option {
	return optionFunc(func(s *scopeConfig) {
		s.aggregationLabelCheck = enabled
	})
}
