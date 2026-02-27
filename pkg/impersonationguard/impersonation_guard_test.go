package impersonationguard

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	return s
}

func TestReconcile_StripsImpersonateVerb(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
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
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	// Verify the ClusterRole was updated
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// The impersonate-only rule on serviceaccounts should be removed entirely,
	// leaving 2 rules
	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules after stripping, got %d: %+v", len(updated.Rules), updated.Rules)
	}

	// Verify no rule contains impersonate
	for i, rule := range updated.Rules {
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				t.Errorf("rule[%d] still contains impersonate verb: %+v", i, rule)
			}
		}
	}

	// Verify autoupdate annotation is set to false
	if updated.Annotations[AutoUpdateAnnotation] != "false" {
		t.Errorf("expected annotation %s = \"false\", got %q",
			AutoUpdateAnnotation, updated.Annotations[AutoUpdateAnnotation])
	}
}

func TestReconcile_RemovesImpersonateFromMixedVerbs(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list", "impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// Rule should remain but with impersonate removed
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(updated.Rules))
	}

	expectedVerbs := []string{"get", "list"}
	if len(updated.Rules[0].Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d: %v", len(expectedVerbs), len(updated.Rules[0].Verbs), updated.Rules[0].Verbs)
	}
	for i, v := range expectedVerbs {
		if updated.Rules[0].Verbs[i] != v {
			t.Errorf("expected verb[%d] = %q, got %q", i, v, updated.Rules[0].Verbs[i])
		}
	}

	// Verify autoupdate annotation is set
	if updated.Annotations[AutoUpdateAnnotation] != "false" {
		t.Errorf("expected annotation %s = \"false\", got %q",
			AutoUpdateAnnotation, updated.Annotations[AutoUpdateAnnotation])
	}
}

func TestReconcile_NoOpWhenAlreadyClean(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
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
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// Verify no modification -- rules should remain the same
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}

	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(updated.Rules))
	}

	// Annotation should NOT be set since no modification was needed
	if _, exists := updated.Annotations[AutoUpdateAnnotation]; exists {
		t.Errorf("expected no autoupdate annotation on unmodified ClusterRole")
	}
}

func TestReconcile_ClusterRoleNotFound(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile should not error on NotFound, got: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}
}

func TestReconcile_IgnoresOtherClusterRoles(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-other-clusterrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "some-other-clusterrole"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// Verify ClusterRole was NOT modified
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "some-other-clusterrole"}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}

	// Rule should still have impersonate
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(updated.Rules))
	}
	foundImpersonate := false
	for _, v := range updated.Rules[0].Verbs {
		if v == "impersonate" {
			foundImpersonate = true
			break
		}
	}
	if !foundImpersonate {
		t.Error("expected impersonate verb to remain in non-target ClusterRole")
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
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
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}

	// First reconcile
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first Reconcile returned error: %v", err)
	}

	// Get state after first reconcile
	after1 := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, after1); err != nil {
		t.Fatalf("failed to get ClusterRole after first reconcile: %v", err)
	}

	// Second reconcile
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("second Reconcile returned error: %v", err)
	}

	// Get state after second reconcile
	after2 := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, after2); err != nil {
		t.Fatalf("failed to get ClusterRole after second reconcile: %v", err)
	}

	// Verify same number of rules
	if len(after1.Rules) != len(after2.Rules) {
		t.Fatalf("rules changed between reconciles: %d vs %d", len(after1.Rules), len(after2.Rules))
	}

	// Verify same rules content
	if len(after2.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(after2.Rules))
	}

	// Verify no impersonate in either
	for _, rule := range after2.Rules {
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				t.Error("impersonate verb found after second reconcile")
			}
		}
	}
}

func TestReconcile_WildcardResourceNotStripped(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}

	// The impersonate-only rule on serviceaccounts should be removed entirely
	// The pods rule should be preserved
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule (pods only), got %d: %+v", len(updated.Rules), updated.Rules)
	}

	// Verify the remaining rule is the pods rule
	if len(updated.Rules[0].Resources) != 1 || updated.Rules[0].Resources[0] != "pods" {
		t.Errorf("expected remaining rule to be for pods, got %v", updated.Rules[0].Resources)
	}

	expectedVerbs := []string{"get", "list", "watch"}
	if len(updated.Rules[0].Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d", len(expectedVerbs), len(updated.Rules[0].Verbs))
	}
	for i, v := range expectedVerbs {
		if updated.Rules[0].Verbs[i] != v {
			t.Errorf("expected verb[%d] = %q, got %q", i, v, updated.Rules[0].Verbs[i])
		}
	}
}

func TestReconcile_StripsWildcardResourceRule(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// The wildcard resource rule with impersonate should be removed entirely,
	// leaving 2 rules (pods and configmaps)
	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules after stripping, got %d: %+v", len(updated.Rules), updated.Rules)
	}

	// Verify no rule contains impersonate
	for i, rule := range updated.Rules {
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				t.Errorf("rule[%d] still contains impersonate verb: %+v", i, rule)
			}
		}
	}

	// Verify autoupdate annotation is set to false
	if updated.Annotations[AutoUpdateAnnotation] != "false" {
		t.Errorf("expected annotation %s = \"false\", got %q",
			AutoUpdateAnnotation, updated.Annotations[AutoUpdateAnnotation])
	}
}

func TestReconcile_StripsWildcardVerbRule(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
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
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// The serviceaccounts rule with wildcard verb should be removed entirely,
	// leaving 2 rules (pods and configmaps)
	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules after stripping, got %d: %+v", len(updated.Rules), updated.Rules)
	}

	// Verify no rule targets serviceaccounts
	for i, rule := range updated.Rules {
		for _, res := range rule.Resources {
			if res == "serviceaccounts" {
				t.Errorf("rule[%d] still targets serviceaccounts: %+v", i, rule)
			}
		}
	}

	// Verify autoupdate annotation is set to false
	if updated.Annotations[AutoUpdateAnnotation] != "false" {
		t.Errorf("expected annotation %s = \"false\", got %q",
			AutoUpdateAnnotation, updated.Annotations[AutoUpdateAnnotation])
	}
}

func TestReconcile_StripsWildcardBothRule(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: TargetClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: TargetClusterRole}}
	result, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if result != (reconcile.Result{}) {
		t.Errorf("expected empty result, got %+v", result)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: TargetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// The wildcard/wildcard rule should be removed entirely,
	// leaving 2 rules (pods and configmaps)
	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules after stripping, got %d: %+v", len(updated.Rules), updated.Rules)
	}

	// Verify no rule has wildcards
	for i, rule := range updated.Rules {
		for _, res := range rule.Resources {
			if res == "*" {
				t.Errorf("rule[%d] still has wildcard resource: %+v", i, rule)
			}
		}
		for _, verb := range rule.Verbs {
			if verb == "*" {
				t.Errorf("rule[%d] still has wildcard verb: %+v", i, rule)
			}
		}
	}

	// Verify autoupdate annotation is set to false
	if updated.Annotations[AutoUpdateAnnotation] != "false" {
		t.Errorf("expected annotation %s = \"false\", got %q",
			AutoUpdateAnnotation, updated.Annotations[AutoUpdateAnnotation])
	}
}
