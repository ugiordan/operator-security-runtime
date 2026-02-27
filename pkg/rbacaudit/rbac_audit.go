package rbacaudit

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// aggregateToEditName is the well-known ClusterRole that aggregates into
	// the edit and admin roles.
	aggregateToEditName = "system:aggregate-to-edit"
)

// Severity indicates the urgency of a Finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
)

// Category classifies the type of RBAC exposure found.
type Category string

const (
	CategoryImpersonationExposure Category = "impersonation-exposure"
	CategoryTokenRequestExposure  Category = "token-request-exposure"
	CategoryAuditError            Category = "rbac-audit-error"
)

// Finding represents a single RBAC audit finding.
type Finding struct {
	Severity    Severity
	Category    Category
	Resource    string
	Description string
}

// AuditImpersonationExposure scans the cluster's RBAC configuration for known
// attack vectors related to impersonation and token request exposure. It runs
// four checks:
//
//  1. Whether system:aggregate-to-edit grants impersonate on serviceaccounts
//     (critical — this is the default Kubernetes CVE-adjacent misconfiguration).
//  2. Whether any other ClusterRole grants impersonate on serviceaccounts
//     (warning — custom roles may intentionally grant this).
//  3. Whether any ClusterRole grants create on serviceaccounts/token
//     (warning — allows obtaining tokens for arbitrary ServiceAccounts).
//  4. Whether any namespace-scoped Role grants impersonate on serviceaccounts
//     (warning — impersonation granted via a Role is scoped to that namespace's SAs).
func AuditImpersonationExposure(ctx context.Context, c client.Reader) []Finding {
	var findings []Finding

	// Check 1: system:aggregate-to-edit
	findings = append(findings, checkAggregateToEdit(ctx, c)...)

	// Checks 2 and 3: scan all ClusterRoles
	findings = append(findings, scanClusterRoles(ctx, c)...)

	// Check 4: scan namespace-scoped Roles
	findings = append(findings, scanRoles(ctx, c)...)

	return findings
}

// checkAggregateToEdit inspects the system:aggregate-to-edit ClusterRole for
// impersonate on serviceaccounts.
func checkAggregateToEdit(ctx context.Context, c client.Reader) []Finding {
	cr := &rbacv1.ClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: aggregateToEditName}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			// ClusterRole does not exist; nothing to report.
			return nil
		}
		return []Finding{{
			Severity:    SeverityWarning,
			Category:    CategoryAuditError,
			Resource:    aggregateToEditName,
			Description: fmt.Sprintf("failed to get ClusterRole %s: %v", aggregateToEditName, err),
		}}
	}

	if hasImpersonateOnServiceAccounts(cr.Rules) {
		return []Finding{{
			Severity:    SeverityCritical,
			Category:    CategoryImpersonationExposure,
			Resource:    aggregateToEditName,
			Description: "system:aggregate-to-edit grants impersonate on serviceaccounts; any namespace editor can impersonate any SA in their namespace",
		}}
	}

	return nil
}

// scanClusterRoles iterates over all ClusterRoles looking for impersonate on
// serviceaccounts (excluding system:aggregate-to-edit, which is checked
// separately) and create on serviceaccounts/token.
func scanClusterRoles(ctx context.Context, c client.Reader) []Finding {
	var findings []Finding

	list := &rbacv1.ClusterRoleList{}
	if err := c.List(ctx, list); err != nil {
		return []Finding{{
			Severity:    SeverityWarning,
			Category:    CategoryAuditError,
			Resource:    "ClusterRoleList",
			Description: fmt.Sprintf("failed to list ClusterRoles: %v", err),
		}}
	}

	for i := range list.Items {
		cr := &list.Items[i]

		// Skip the aggregate-to-edit role; it has its own dedicated check.
		if cr.Name == aggregateToEditName {
			continue
		}

		if hasImpersonateOnServiceAccounts(cr.Rules) {
			findings = append(findings, Finding{
				Severity:    SeverityWarning,
				Category:    CategoryImpersonationExposure,
				Resource:    cr.Name,
				Description: fmt.Sprintf("ClusterRole %s grants impersonate on serviceaccounts", cr.Name),
			})
		}

		if hasTokenRequestCreate(cr.Rules) {
			findings = append(findings, Finding{
				Severity:    SeverityWarning,
				Category:    CategoryTokenRequestExposure,
				Resource:    cr.Name,
				Description: fmt.Sprintf("ClusterRole %s grants create on serviceaccounts/token", cr.Name),
			})
		}
	}

	return findings
}

// hasImpersonateOnServiceAccounts returns true if any rule grants the
// impersonate verb on serviceaccounts.
func hasImpersonateOnServiceAccounts(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if contains(rule.Resources, "serviceaccounts") && contains(rule.Verbs, "impersonate") {
			return true
		}
	}
	return false
}

// scanRoles iterates over all namespace-scoped Roles looking for impersonate
// on serviceaccounts. While impersonation is typically granted via ClusterRoles,
// a namespace-scoped Role can grant impersonation of SAs within that namespace.
func scanRoles(ctx context.Context, c client.Reader) []Finding {
	var findings []Finding

	list := &rbacv1.RoleList{}
	if err := c.List(ctx, list); err != nil {
		return []Finding{{
			Severity:    SeverityWarning,
			Category:    CategoryAuditError,
			Resource:    "RoleList",
			Description: fmt.Sprintf("failed to list Roles: %v", err),
		}}
	}

	for i := range list.Items {
		r := &list.Items[i]
		if hasImpersonateOnServiceAccounts(r.Rules) {
			findings = append(findings, Finding{
				Severity:    SeverityWarning,
				Category:    CategoryImpersonationExposure,
				Resource:    fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name),
				Description: fmt.Sprintf("Role %s/%s grants impersonate on serviceaccounts", r.Namespace, r.Name),
			})
		}
	}

	return findings
}

// hasTokenRequestCreate returns true if any rule grants the create verb on
// serviceaccounts/token (the TokenRequest subresource). Also matches the
// subresource wildcard serviceaccounts/*.
func hasTokenRequestCreate(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		hasCreate := contains(rule.Verbs, "create")
		if !hasCreate {
			continue
		}
		if contains(rule.Resources, "serviceaccounts/token") || contains(rule.Resources, "serviceaccounts/*") {
			return true
		}
	}
	return false
}

// contains checks whether the slice contains the target or a wildcard ("*").
func contains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target || s == "*" {
			return true
		}
	}
	return false
}
