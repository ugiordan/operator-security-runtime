package rbacscope

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
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
// explicit rules, or AllowAllRules to allow arbitrary per-call rules.
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

// AllowAllRules returns an AllowedRules that permits arbitrary rules.
func AllowAllRules() AllowedRules {
	return AllowedRules{allowAll: true}
}
