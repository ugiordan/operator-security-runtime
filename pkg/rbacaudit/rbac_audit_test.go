package rbacaudit

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	return s
}

func TestAuditImpersonationExposure_DetectsDefaultImpersonate(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	// Must have at least one critical finding for the default impersonate exposure.
	var criticalCount int
	for _, f := range findings {
		if f.Severity == SeverityCritical && f.Category == CategoryImpersonationExposure {
			criticalCount++
			if f.Resource != "system:aggregate-to-edit" {
				t.Errorf("expected Resource = system:aggregate-to-edit, got %q", f.Resource)
			}
		}
	}
	if criticalCount == 0 {
		t.Fatal("expected at least one critical impersonation-exposure finding, got none")
	}
}

func TestAuditImpersonationExposure_CleanCluster(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	// No critical findings expected.
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			t.Errorf("unexpected critical finding: %+v", f)
		}
	}
}

func TestAuditImpersonationExposure_DetectsCustomImpersonateRole(t *testing.T) {
	s := testScheme()
	// Create a clean system:aggregate-to-edit (no impersonate).
	aggregateRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	// Create a custom role that grants impersonate on serviceaccounts.
	customRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "custom-impersonate-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(aggregateRole, customRole).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	// Expect a warning for the custom role.
	var found bool
	for _, f := range findings {
		if f.Severity == SeverityWarning && f.Category == CategoryImpersonationExposure && f.Resource == "custom-impersonate-role" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a warning finding for custom-impersonate-role, got none")
	}

	// Should not have any critical findings (aggregate-to-edit is clean).
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			t.Errorf("unexpected critical finding: %+v", f)
		}
	}
}

func TestAuditImpersonationExposure_DetectsTokenRequestExposure(t *testing.T) {
	s := testScheme()
	// Create a clean system:aggregate-to-edit.
	aggregateRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	// Create a role that grants create on serviceaccounts/token.
	tokenRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "token-creator-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(aggregateRole, tokenRole).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	// Expect a warning for token-request-exposure.
	var found bool
	for _, f := range findings {
		if f.Severity == SeverityWarning && f.Category == CategoryTokenRequestExposure && f.Resource == "token-creator-role" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a warning finding for token-creator-role with category token-request-exposure, got none")
	}
}

func TestAuditImpersonationExposure_ClusterRoleMissing(t *testing.T) {
	s := testScheme()
	// No system:aggregate-to-edit exists in the cluster.
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	// No critical findings expected, and no panic.
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			t.Errorf("unexpected critical finding when ClusterRole is missing: %+v", f)
		}
	}
}

func TestAuditImpersonationExposure_DetectsNamespacedRoleImpersonate(t *testing.T) {
	s := testScheme()
	// Clean system:aggregate-to-edit.
	aggregateRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	// Namespace-scoped Role granting impersonate on serviceaccounts.
	nsRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns-impersonate-role",
			Namespace: "target-ns",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(aggregateRole, nsRole).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	var found bool
	for _, f := range findings {
		if f.Severity == SeverityWarning && f.Category == CategoryImpersonationExposure && f.Resource == "Role/target-ns/ns-impersonate-role" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a warning finding for namespace-scoped Role with impersonate, got none")
	}
}

func TestAuditImpersonationExposure_DetectsSubresourceWildcard(t *testing.T) {
	s := testScheme()
	aggregateRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:aggregate-to-edit",
		},
		Rules: []rbacv1.PolicyRule{},
	}
	// ClusterRole with serviceaccounts/* (subresource wildcard).
	tokenWildcardRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sa-subresource-wildcard",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/*"},
				Verbs:     []string{"create"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(aggregateRole, tokenWildcardRole).Build()
	ctx := context.Background()

	findings := AuditImpersonationExposure(ctx, cl)

	var found bool
	for _, f := range findings {
		if f.Severity == SeverityWarning && f.Category == CategoryTokenRequestExposure && f.Resource == "sa-subresource-wildcard" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a warning finding for serviceaccounts/* subresource wildcard, got none")
	}
}
