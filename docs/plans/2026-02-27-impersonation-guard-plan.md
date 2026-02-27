# Impersonation Guard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Block impersonation attacks (`kubectl --as=system:serviceaccount:<ns>:<sa>`) that bypass the SA protection webhook, by stripping the `impersonate` verb from `system:aggregate-to-edit` and auditing RBAC exposure at startup.

**Architecture:** Three independent packages: (1) `pkg/impersonationguard` — a controller-runtime reconciler that watches `system:aggregate-to-edit` and strips the `impersonate` verb, (2) `pkg/rbacaudit` — a startup function that scans for impersonation/token-request exposure and returns findings, (3) `config/validatingadmissionpolicy/` — YAML artifacts to prevent new impersonation grants.

**Tech Stack:** Go 1.22, controller-runtime v0.19, Kubernetes RBAC API (`rbacv1`), ValidatingAdmissionPolicy (K8s 1.30+)

---

### Task 1: Fix Incorrect Impersonation Documentation

The `TECHNICAL_DESIGN.md` incorrectly states that `impersonate` is NOT in default Kubernetes roles. In fact, `system:aggregate-to-edit` grants `impersonate` on `serviceaccounts` by default, aggregating into `edit` and `admin`. Fix all incorrect statements.

**Files:**
- Modify: `docs/TECHNICAL_DESIGN.md` (lines 178, 460, 468)

**Step 1: Fix line 178 — SA impersonation scenario**

Replace:
```
**ServiceAccount impersonation.** Result: Allowed (if impersonating the operator SA itself). This is acceptable because impersonation requires explicit RBAC grants (`impersonate` verb) that are not present in default roles.
```
With:
```
**ServiceAccount impersonation.** Result: Allowed (if impersonating the operator SA itself). This is a known gap: the default Kubernetes `system:aggregate-to-edit` ClusterRole grants `impersonate` on `serviceaccounts`, which aggregates into `edit` and `admin` roles. Any namespace editor can impersonate SAs in their namespace. The `pkg/impersonationguard` package addresses this by stripping the `impersonate` verb from `system:aggregate-to-edit`.
```

**Step 2: Fix line 460 — bypass FAQ**

Replace:
```
A: Only via ServiceAccount impersonation, which requires explicit RBAC grants (`impersonate` verb) not present in default roles. This vector should be addressed via complementary RBAC restrictions on impersonation.
```
With:
```
A: Via ServiceAccount impersonation. The default Kubernetes `system:aggregate-to-edit` ClusterRole grants `impersonate` on `serviceaccounts`, which aggregates into `edit` and `admin` — meaning any namespace editor can bypass the webhook. Use `pkg/impersonationguard` to strip this default grant, or deploy the ValidatingAdmissionPolicy artifacts to prevent new impersonation grants.
```

**Step 3: Fix line 468 — known limitations**

Replace:
```
**Impersonation bypass.** Users with the `impersonate` RBAC verb can assume the operator's identity. The webhook allows requests from the operator's identity regardless of whether the identity is direct or impersonated. Mitigation: restrict `impersonate` grants via RBAC policy. Impersonation requires explicit RBAC grants that are not present in default roles.
```
With:
```
**Impersonation bypass.** Users with the `impersonate` RBAC verb can assume the operator's identity. The webhook allows requests from the operator's identity regardless of whether the identity is direct or impersonated. The default `system:aggregate-to-edit` ClusterRole grants `impersonate` on `serviceaccounts`, aggregating into `edit` and `admin` — this means **any namespace editor can bypass the webhook by default**. Mitigation: use `pkg/impersonationguard` to strip the `impersonate` verb from `system:aggregate-to-edit`, and deploy the ValidatingAdmissionPolicy to prevent new impersonation grants. See the Integration Guide Section 6 for details.
```

**Step 4: Verify no other incorrect statements remain**

Run: `grep -n "not present in default" docs/TECHNICAL_DESIGN.md`
Expected: No matches

**Step 5: Commit**

```bash
git add docs/TECHNICAL_DESIGN.md
git commit -m "fix: correct incorrect claims about impersonation not being in default roles"
```

---

### Task 2: Create `pkg/impersonationguard` — Failing Tests

Write the test file first. The reconciler watches `system:aggregate-to-edit` and strips `impersonate` from rules targeting `serviceaccounts`.

**Files:**
- Create: `pkg/impersonationguard/doc.go`
- Create: `pkg/impersonationguard/impersonation_guard_test.go`

**Step 1: Create `doc.go`**

```go
// Package impersonationguard provides a controller-runtime reconciler that
// hardens Kubernetes RBAC by stripping the `impersonate` verb from the
// `system:aggregate-to-edit` ClusterRole. By default, this ClusterRole grants
// `impersonate` on `serviceaccounts`, which aggregates into the `edit` and
// `admin` roles — allowing any namespace editor to impersonate any
// ServiceAccount in their namespace. This bypasses the SA protection webhook
// entirely because impersonation is processed at the Kubernetes authentication
// layer, before admission webhooks fire.
//
// The reconciler watches `system:aggregate-to-edit` and continuously ensures
// the `impersonate` verb is removed. It also sets the annotation
// `rbac.authorization.kubernetes.io/autoupdate: "false"` to prevent the
// Kubernetes RBAC controller from re-adding the verb on API server restart.
//
// Usage:
//
//	if err := (&impersonationguard.ImpersonationGuardReconciler{
//	    Client: mgr.GetClient(),
//	    Scheme: mgr.GetScheme(),
//	}).SetupWithManager(mgr); err != nil {
//	    setupLog.Error(err, "unable to create impersonation guard")
//	    os.Exit(1)
//	}
package impersonationguard
```

**Step 2: Create test file with all test cases**

```go
package impersonationguard

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const targetClusterRole = "system:aggregate-to-edit"

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	return s
}

// clusterRoleWithImpersonate creates a system:aggregate-to-edit ClusterRole
// that contains the impersonate verb on serviceaccounts (the Kubernetes default).
func clusterRoleWithImpersonate() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: targetClusterRole,
			Labels: map[string]string{
				"rbac.authorization.k8s.io/aggregate-to-edit": "true",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

// clusterRoleWithoutImpersonate creates a system:aggregate-to-edit ClusterRole
// that does NOT contain the impersonate verb.
func clusterRoleWithoutImpersonate() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: targetClusterRole,
			Labels: map[string]string{
				"rbac.authorization.k8s.io/aggregate-to-edit": "true",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch", "create", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

// clusterRoleWithMixedVerbs creates a rule where impersonate is mixed with other verbs.
func clusterRoleWithMixedVerbs() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: targetClusterRole,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list", "impersonate"},
			},
		},
	}
}

func TestReconcile_StripsImpersonateVerb(t *testing.T) {
	s := testScheme()
	cr := clusterRoleWithImpersonate()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// Verify the ClusterRole was updated
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: targetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// Verify impersonate rule is gone
	for _, rule := range updated.Rules {
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				t.Errorf("expected impersonate verb to be removed, but found it in rule: %+v", rule)
			}
		}
	}

	// Verify other rules are preserved
	if len(updated.Rules) != 2 {
		t.Errorf("expected 2 rules (pods + services) after stripping, got %d", len(updated.Rules))
	}

	// Verify autoupdate annotation is set
	if updated.Annotations["rbac.authorization.kubernetes.io/autoupdate"] != "false" {
		t.Errorf("expected autoupdate annotation to be 'false', got %q",
			updated.Annotations["rbac.authorization.kubernetes.io/autoupdate"])
	}
}

func TestReconcile_RemovesImpersonateFromMixedVerbs(t *testing.T) {
	s := testScheme()
	cr := clusterRoleWithMixedVerbs()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: targetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get updated ClusterRole: %v", err)
	}

	// Rule should survive but without impersonate
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule after stripping impersonate, got %d", len(updated.Rules))
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
}

func TestReconcile_NoOpWhenAlreadyClean(t *testing.T) {
	s := testScheme()
	cr := clusterRoleWithoutImpersonate()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// Verify ClusterRole was not modified (no annotation added when not needed)
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: targetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}
	if len(updated.Rules) != 2 {
		t.Errorf("expected 2 rules unchanged, got %d", len(updated.Rules))
	}
}

func TestReconcile_ClusterRoleNotFound(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	// Should not error when ClusterRole doesn't exist
	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error when ClusterRole not found: %v", err)
	}
}

func TestReconcile_IgnoresOtherClusterRoles(t *testing.T) {
	s := testScheme()
	other := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "some-other-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(other).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "some-other-role"},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	// Verify it was NOT modified
	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "some-other-role"}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}
	if len(updated.Rules[0].Verbs) != 1 || updated.Rules[0].Verbs[0] != "impersonate" {
		t.Errorf("expected other ClusterRole to remain unchanged, got verbs: %v", updated.Rules[0].Verbs)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	s := testScheme()
	cr := clusterRoleWithImpersonate()
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	// First reconcile
	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	}); err != nil {
		t.Fatalf("first Reconcile returned error: %v", err)
	}

	// Second reconcile (should be no-op)
	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	}); err != nil {
		t.Fatalf("second Reconcile returned error: %v", err)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: targetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}
	for _, rule := range updated.Rules {
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				t.Errorf("impersonate verb still present after two reconciles")
			}
		}
	}
}

func TestReconcile_WildcardResourceNotStripped(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: targetClusterRole},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	r := &ImpersonationGuardReconciler{Client: cl, Scheme: s}
	ctx := context.Background()

	if _, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: targetClusterRole},
	}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	updated := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: targetClusterRole}, updated); err != nil {
		t.Fatalf("failed to get ClusterRole: %v", err)
	}

	// impersonate-only rule targeting serviceaccounts should be removed entirely
	// pods rule should be preserved
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule (pods only), got %d", len(updated.Rules))
	}
	if updated.Rules[0].Resources[0] != "pods" {
		t.Errorf("expected remaining rule to be for pods, got %v", updated.Rules[0].Resources)
	}
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go test ./pkg/impersonationguard/... -v -count=1`
Expected: FAIL (ImpersonationGuardReconciler not defined)

**Step 4: Commit**

```bash
git add pkg/impersonationguard/
git commit -m "test: add failing tests for ImpersonationGuardReconciler"
```

---

### Task 3: Implement `pkg/impersonationguard` — Reconciler

Write the minimal implementation to make all tests pass.

**Files:**
- Create: `pkg/impersonationguard/impersonation_guard.go`

**Step 1: Write the implementation**

```go
package impersonationguard

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// TargetClusterRole is the name of the ClusterRole that grants impersonate
	// to editors by default via aggregation.
	TargetClusterRole = "system:aggregate-to-edit"

	// AutoUpdateAnnotation is the Kubernetes RBAC controller annotation that
	// controls whether the ClusterRole is automatically restored on API server restart.
	AutoUpdateAnnotation = "rbac.authorization.kubernetes.io/autoupdate"
)

// ImpersonationGuardReconciler watches the system:aggregate-to-edit ClusterRole
// and strips the `impersonate` verb from any rule targeting `serviceaccounts`.
type ImpersonationGuardReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile checks the system:aggregate-to-edit ClusterRole for impersonate
// verbs on serviceaccounts and removes them.
func (r *ImpersonationGuardReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithName("impersonation-guard")

	// Only process the target ClusterRole
	if req.Name != TargetClusterRole {
		return reconcile.Result{}, nil
	}

	cr := &rbacv1.ClusterRole{}
	if err := r.Get(ctx, types.NamespacedName{Name: req.Name}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("target ClusterRole not found, nothing to do")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting ClusterRole %s: %w", req.Name, err)
	}

	modified, newRules := stripImpersonate(cr.Rules)
	if !modified {
		log.Info("no impersonate verbs found on serviceaccounts, nothing to do")
		return reconcile.Result{}, nil
	}

	log.Info("stripping impersonate verb from serviceaccounts rules",
		"originalRuleCount", len(cr.Rules),
		"newRuleCount", len(newRules))

	cr.Rules = newRules

	// Set autoupdate to false to prevent the RBAC controller from restoring
	// the impersonate verb on API server restart
	if cr.Annotations == nil {
		cr.Annotations = make(map[string]string)
	}
	cr.Annotations[AutoUpdateAnnotation] = "false"

	if err := r.Update(ctx, cr); err != nil {
		return reconcile.Result{}, fmt.Errorf("updating ClusterRole %s: %w", req.Name, err)
	}

	log.Info("successfully stripped impersonate verb from system:aggregate-to-edit")
	return reconcile.Result{}, nil
}

// SetupWithManager registers the reconciler to watch only the
// system:aggregate-to-edit ClusterRole.
func (r *ImpersonationGuardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1.ClusterRole{}, builder.WithPredicates(predicate.NewPredicateFuncs(
			func(obj client.Object) bool {
				return obj.GetName() == TargetClusterRole
			},
		))).
		Complete(r)
}

// stripImpersonate removes the `impersonate` verb from any rule that targets
// `serviceaccounts`. If a rule's only verb is `impersonate`, the entire rule
// is removed. Returns whether any modification was made and the new rules slice.
func stripImpersonate(rules []rbacv1.PolicyRule) (bool, []rbacv1.PolicyRule) {
	modified := false
	var result []rbacv1.PolicyRule

	for _, rule := range rules {
		if !targetsServiceAccounts(rule) {
			result = append(result, rule)
			continue
		}

		filtered := removeVerb(rule.Verbs, "impersonate")
		if len(filtered) == len(rule.Verbs) {
			// No impersonate verb in this rule
			result = append(result, rule)
			continue
		}

		modified = true
		if len(filtered) > 0 {
			// Keep the rule with remaining verbs
			rule.Verbs = filtered
			result = append(result, rule)
		}
		// If no verbs remain, drop the entire rule
	}

	return modified, result
}

// targetsServiceAccounts returns true if the rule's Resources includes
// "serviceaccounts".
func targetsServiceAccounts(rule rbacv1.PolicyRule) bool {
	for _, r := range rule.Resources {
		if r == "serviceaccounts" {
			return true
		}
	}
	return false
}

// removeVerb returns a new slice with the specified verb removed.
func removeVerb(verbs []string, target string) []string {
	var result []string
	for _, v := range verbs {
		if v != target {
			result = append(result, v)
		}
	}
	return result
}
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go test ./pkg/impersonationguard/... -v -count=1`
Expected: All 7 tests PASS

**Step 3: Run go vet**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go vet ./pkg/impersonationguard/...`
Expected: No issues

**Step 4: Commit**

```bash
git add pkg/impersonationguard/
git commit -m "feat: add ImpersonationGuardReconciler to strip impersonate from system:aggregate-to-edit"
```

---

### Task 4: Create `pkg/rbacaudit` — Failing Tests

Write the test file for the startup RBAC audit function.

**Files:**
- Create: `pkg/rbacaudit/doc.go`
- Create: `pkg/rbacaudit/rbac_audit_test.go`

**Step 1: Create `doc.go`**

```go
// Package rbacaudit provides startup RBAC audit functions that check for
// impersonation and token request exposure in the cluster's RBAC configuration.
//
// Call AuditImpersonationExposure during operator startup to detect known
// attack vectors and log warnings before the operator begins reconciliation.
//
// Usage:
//
//	findings := rbacaudit.AuditImpersonationExposure(ctx, mgr.GetClient())
//	for _, f := range findings {
//	    setupLog.Info("RBAC audit finding",
//	        "severity", f.Severity,
//	        "category", f.Category,
//	        "resource", f.Resource,
//	        "description", f.Description)
//	}
package rbacaudit
```

**Step 2: Create test file**

```go
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
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	findings := AuditImpersonationExposure(context.Background(), cl)

	found := false
	for _, f := range findings {
		if f.Category == "impersonation" && f.Severity == "critical" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical impersonation finding, got none")
	}
}

func TestAuditImpersonationExposure_CleanCluster(t *testing.T) {
	s := testScheme()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()

	findings := AuditImpersonationExposure(context.Background(), cl)

	for _, f := range findings {
		if f.Category == "impersonation" && f.Severity == "critical" {
			t.Errorf("unexpected critical impersonation finding: %s", f.Description)
		}
	}
}

func TestAuditImpersonationExposure_DetectsCustomImpersonateRole(t *testing.T) {
	s := testScheme()
	// Clean system:aggregate-to-edit
	systemRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		}},
	}
	// Custom role with impersonate
	customRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-impersonator"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(systemRole, customRole).Build()

	findings := AuditImpersonationExposure(context.Background(), cl)

	found := false
	for _, f := range findings {
		if f.Category == "impersonation" && f.Resource == "ClusterRole/custom-impersonator" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for custom impersonator role, got none")
	}
}

func TestAuditImpersonationExposure_DetectsTokenRequestExposure(t *testing.T) {
	s := testScheme()
	systemRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules:      []rbacv1.PolicyRule{},
	}
	tokenRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "token-minter"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(systemRole, tokenRole).Build()

	findings := AuditImpersonationExposure(context.Background(), cl)

	found := false
	for _, f := range findings {
		if f.Category == "token-request" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected token-request finding, got none")
	}
}

func TestAuditImpersonationExposure_ClusterRoleMissing(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	// Should not panic or error when system:aggregate-to-edit doesn't exist
	findings := AuditImpersonationExposure(context.Background(), cl)

	// No critical findings expected when the target role is absent
	for _, f := range findings {
		if f.Category == "impersonation" && f.Severity == "critical" {
			t.Errorf("unexpected critical finding when ClusterRole is missing: %s", f.Description)
		}
	}
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go test ./pkg/rbacaudit/... -v -count=1`
Expected: FAIL (AuditImpersonationExposure not defined)

**Step 4: Commit**

```bash
git add pkg/rbacaudit/
git commit -m "test: add failing tests for RBAC audit function"
```

---

### Task 5: Implement `pkg/rbacaudit` — Audit Function

Write the minimal implementation to make all tests pass.

**Files:**
- Create: `pkg/rbacaudit/rbac_audit.go`

**Step 1: Write the implementation**

```go
package rbacaudit

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Finding represents a single RBAC audit finding.
type Finding struct {
	// Severity is the finding severity: "critical", "warning", or "info".
	Severity string
	// Category is the finding category: "impersonation" or "token-request".
	Category string
	// Resource is the Kubernetes resource that triggered the finding,
	// e.g., "ClusterRole/system:aggregate-to-edit".
	Resource string
	// Description is a human-readable description of the finding.
	Description string
}

// AuditImpersonationExposure checks the cluster's RBAC configuration for
// impersonation and token request exposure. Returns a slice of findings that
// callers can log, emit as events, or report to monitoring.
//
// Checks performed:
//  1. system:aggregate-to-edit ClusterRole contains impersonate on serviceaccounts
//  2. Other ClusterRoles with impersonate on serviceaccounts
//  3. ClusterRoles with create on serviceaccounts/token
func AuditImpersonationExposure(ctx context.Context, c client.Client) []Finding {
	var findings []Finding

	// Check 1: system:aggregate-to-edit
	findings = append(findings, checkAggregateToEdit(ctx, c)...)

	// Check 2 & 3: scan all ClusterRoles
	findings = append(findings, scanClusterRoles(ctx, c)...)

	return findings
}

func checkAggregateToEdit(ctx context.Context, c client.Client) []Finding {
	cr := &rbacv1.ClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: "system:aggregate-to-edit"}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return []Finding{{
			Severity:    "warning",
			Category:    "impersonation",
			Resource:    "ClusterRole/system:aggregate-to-edit",
			Description: fmt.Sprintf("failed to read system:aggregate-to-edit: %v", err),
		}}
	}

	for _, rule := range cr.Rules {
		if hasImpersonateOnServiceAccounts(rule) {
			return []Finding{{
				Severity: "critical",
				Category: "impersonation",
				Resource: "ClusterRole/system:aggregate-to-edit",
				Description: "system:aggregate-to-edit grants 'impersonate' on serviceaccounts; " +
					"this aggregates into edit and admin roles, allowing any namespace " +
					"editor to impersonate ServiceAccounts and bypass the SA protection webhook",
			}}
		}
	}

	return nil
}

func scanClusterRoles(ctx context.Context, c client.Client) []Finding {
	var findings []Finding

	list := &rbacv1.ClusterRoleList{}
	if err := c.List(ctx, list); err != nil {
		return []Finding{{
			Severity:    "warning",
			Category:    "impersonation",
			Resource:    "ClusterRoleList",
			Description: fmt.Sprintf("failed to list ClusterRoles: %v", err),
		}}
	}

	for i := range list.Items {
		cr := &list.Items[i]
		// Skip the system:aggregate-to-edit (already checked separately)
		if cr.Name == "system:aggregate-to-edit" {
			continue
		}

		for _, rule := range cr.Rules {
			if hasImpersonateOnServiceAccounts(rule) {
				findings = append(findings, Finding{
					Severity: "warning",
					Category: "impersonation",
					Resource: fmt.Sprintf("ClusterRole/%s", cr.Name),
					Description: fmt.Sprintf("ClusterRole %q grants 'impersonate' on serviceaccounts; "+
						"subjects bound to this role can impersonate ServiceAccounts and bypass the SA protection webhook",
						cr.Name),
				})
			}

			if hasTokenRequestCreate(rule) {
				findings = append(findings, Finding{
					Severity: "warning",
					Category: "token-request",
					Resource: fmt.Sprintf("ClusterRole/%s", cr.Name),
					Description: fmt.Sprintf("ClusterRole %q grants 'create' on serviceaccounts/token; "+
						"subjects bound to this role can mint tokens for any ServiceAccount without creating a pod",
						cr.Name),
				})
			}
		}
	}

	return findings
}

func hasImpersonateOnServiceAccounts(rule rbacv1.PolicyRule) bool {
	hasSA := false
	for _, r := range rule.Resources {
		if r == "serviceaccounts" {
			hasSA = true
			break
		}
	}
	if !hasSA {
		return false
	}

	for _, v := range rule.Verbs {
		if v == "impersonate" {
			return true
		}
	}
	return false
}

func hasTokenRequestCreate(rule rbacv1.PolicyRule) bool {
	hasToken := false
	for _, r := range rule.Resources {
		if r == "serviceaccounts/token" {
			hasToken = true
			break
		}
	}
	if !hasToken {
		return false
	}

	for _, v := range rule.Verbs {
		if v == "create" {
			return true
		}
	}
	return false
}
```

**Step 2: Run tests to verify they pass**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go test ./pkg/rbacaudit/... -v -count=1`
Expected: All 5 tests PASS

**Step 3: Run go vet**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go vet ./pkg/rbacaudit/...`
Expected: No issues

**Step 4: Commit**

```bash
git add pkg/rbacaudit/
git commit -m "feat: add RBAC audit function for impersonation and token request exposure"
```

---

### Task 6: Create ValidatingAdmissionPolicy Artifacts

Create YAML manifests that prevent non-system users from creating new RBAC resources with the `impersonate` verb.

**Files:**
- Create: `config/validatingadmissionpolicy/deny-impersonate-grants.yaml`

**Step 1: Create the policy YAML**

```yaml
# ValidatingAdmissionPolicy to prevent non-system users from creating or
# updating ClusterRoles/Roles that grant the 'impersonate' verb on
# serviceaccounts.
#
# Requires Kubernetes 1.30+ (ValidatingAdmissionPolicy GA).
# On OpenShift, available from OCP 4.17+.
#
# Deploy with:
#   kubectl apply -f config/validatingadmissionpolicy/
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-impersonate-grants
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["rbac.authorization.k8s.io"]
        apiVersions: ["v1"]
        resources: ["clusterroles", "roles"]
        operations: ["CREATE", "UPDATE"]
  matchConditions:
    - name: not-system-user
      expression: "!request.userInfo.username.startsWith('system:')"
  validations:
    - expression: |
        !object.rules.exists(r,
          r.verbs.exists(v, v == 'impersonate') &&
          r.resources.exists(res, res == 'serviceaccounts' || res == '*')
        )
      message: "Granting 'impersonate' on serviceaccounts is restricted. Contact your cluster admin."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-impersonate-grants-binding
spec:
  policyName: deny-impersonate-grants
  validationActions:
    - Deny
```

**Step 2: Verify YAML is valid**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && python3 -c "import yaml; list(yaml.safe_load_all(open('config/validatingadmissionpolicy/deny-impersonate-grants.yaml')))" 2>/dev/null || echo "install pyyaml or skip"`

If python/pyyaml not available, use: `cat config/validatingadmissionpolicy/deny-impersonate-grants.yaml | head -5` to confirm file exists.

**Step 3: Commit**

```bash
git add config/validatingadmissionpolicy/
git commit -m "feat: add ValidatingAdmissionPolicy to block new impersonation grants"
```

---

### Task 7: Update Example Operator

Update the example operator to demonstrate the impersonation guard and RBAC audit.

**Files:**
- Modify: `examples/operator/cmd/main.go`

**Step 1: Read current `main.go`**

Read `examples/operator/cmd/main.go` to understand the existing structure.

**Step 2: Add impersonation guard and RBAC audit imports and calls**

Add after the existing webhook setup:

```go
import (
	// ... existing imports ...
	"github.com/opendatahub-io/operator-security-runtime/pkg/impersonationguard"
	"github.com/opendatahub-io/operator-security-runtime/pkg/rbacaudit"
)

// After manager creation, before mgr.Start():

// Run startup RBAC audit
findings := rbacaudit.AuditImpersonationExposure(context.Background(), mgr.GetClient())
for _, f := range findings {
	setupLog.Info("RBAC audit finding",
		"severity", f.Severity,
		"category", f.Category,
		"resource", f.Resource,
		"description", f.Description)
}

// Register impersonation guard
if err := (&impersonationguard.ImpersonationGuardReconciler{
	Client: mgr.GetClient(),
	Scheme: mgr.GetScheme(),
}).SetupWithManager(mgr); err != nil {
	setupLog.Error(err, "unable to create impersonation guard controller")
	os.Exit(1)
}
```

**Step 3: Verify build**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go build ./...`
Expected: No errors

**Step 4: Commit**

```bash
git add examples/operator/cmd/main.go
git commit -m "feat: add impersonation guard and RBAC audit to example operator"
```

---

### Task 8: Update Documentation

Update README.md, TECHNICAL_DESIGN.md, and INTEGRATION_GUIDE.md to document the new packages.

**Files:**
- Modify: `README.md`
- Modify: `docs/TECHNICAL_DESIGN.md`
- Modify: `docs/INTEGRATION_GUIDE.md`

**Step 1: Update README.md**

Add to the "How It Works" table a third row for impersonation guard. Add a new `### pkg/impersonationguard` section after the existing package sections. Add a `### pkg/rbacaudit` section. Update the Quick Start with impersonation guard setup. Update Defense in Depth section to reference the new components.

**Step 2: Update INTEGRATION_GUIDE.md**

Add a new section (between Section 3 and Section 4) for integrating the impersonation guard. Update Section 6 (Complementary RBAC Hardening) to reference the new automated approach instead of the manual YAML.

**Step 3: Update TECHNICAL_DESIGN.md**

Add architecture description for the impersonation guard reconciler. Update the known limitations section with the automated mitigation. Add the ValidatingAdmissionPolicy to the defense layers description.

**Step 4: Commit**

```bash
git add README.md docs/TECHNICAL_DESIGN.md docs/INTEGRATION_GUIDE.md
git commit -m "docs: document impersonation guard, RBAC audit, and ValidatingAdmissionPolicy"
```

---

### Task 9: Full Verification

Run all tests, build, and vet across the entire project.

**Step 1: Run all tests**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go test ./pkg/... -v -count=1`
Expected: All tests pass (impersonationguard, rbacaudit, rbacscope, saprotection)

**Step 2: Build entire project**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go build ./...`
Expected: No errors

**Step 3: Run go vet**

Run: `cd /Users/ugogiordano/workdir/rhoai/opendatahub-io/operator-security-runtime && go vet ./pkg/...`
Expected: No issues

---

### Task 10: Architect Review

Spawn sub-agent architects to review the complete implementation:

- API design: Are the package APIs consistent with existing packages (saprotection, rbacscope)?
- Security: Does the reconciler introduce any new attack surface? Can the guard be disabled by an attacker?
- Test coverage: Are edge cases covered? Are there missing scenarios?
- Documentation: Is the integration path clear? Are the threat descriptions accurate?
- ValidatingAdmissionPolicy: Is the CEL expression correct? Are there bypass vectors?

Fix any issues found before marking complete.
