package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/opendatahub-io/operator-security-runtime/pkg/rbacscope"

	appv1alpha1 "github.com/opendatahub-io/operator-security-runtime/examples/operator/api/v1alpha1"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(appv1alpha1.AddToScheme(s))
	utilruntime.Must(rbacv1.AddToScheme(s))
	utilruntime.Must(corev1.AddToScheme(s))
	return s
}

func newTestRBACScoper(t *testing.T, cl client.Client, s *runtime.Scheme) *rbacscope.RBACScoper {
	t.Helper()
	allowed, err := rbacscope.NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules returned error: %v", err)
	}
	scoper, err := rbacscope.NewRBACScoper(
		cl,
		s,
		rbacscope.OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-sa",
			Namespace:      "operator-ns",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper returned error: %v", err)
	}
	return scoper
}

func TestExampleResourceReconciler_CreatesRoleAndRoleBinding(t *testing.T) {
	s := testScheme()
	ctx := context.Background()
	ns := "test-ns"

	cr := &appv1alpha1.ExampleResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: ns,
			UID:       types.UID("uid-123"),
		},
	}
	cr.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "app.example.com",
		Version: "v1alpha1",
		Kind:    "ExampleResource",
	})

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cr).
		WithStatusSubresource(cr).
		Build()

	scoper := newTestRBACScoper(t, fakeClient, s)

	reconciler := &ExampleResourceReconciler{
		Client:     fakeClient,
		Scheme:     s,
		RBACScoper: scoper,
	}

	// First reconcile: should add finalizer
	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-resource", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("first reconcile (add finalizer) returned error: %v", err)
	}
	if result.Requeue || result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue from first reconcile, got %+v", result)
	}

	// Second reconcile: finalizer is present, should ensure RBAC + list secrets
	result, err = reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-resource", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("second reconcile returned error: %v", err)
	}

	// Verify Role was created
	role := &rbacv1.Role{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: ns,
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	if role.Rules[0].Resources[0] != "secrets" {
		t.Errorf("expected rule for secrets, got %v", role.Rules[0].Resources)
	}

	// Verify RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	if err := fakeClient.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: ns,
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if rb.RoleRef.Name != "test-operator-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-scoped-access, got %q", rb.RoleRef.Name)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "test-sa" {
		t.Errorf("expected subject test-sa, got %v", rb.Subjects)
	}
}

func TestExampleResourceReconciler_Deletion(t *testing.T) {
	s := testScheme()
	ctx := context.Background()
	ns := "test-ns"

	now := metav1.Now()
	cr := &appv1alpha1.ExampleResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-resource",
			Namespace:         ns,
			UID:               types.UID("uid-456"),
			DeletionTimestamp: &now,
			Finalizers:        []string{finalizerName},
		},
	}
	cr.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "app.example.com",
		Version: "v1alpha1",
		Kind:    "ExampleResource",
	})

	// Pre-create the Role and RoleBinding that would have been created during normal reconcile
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "app.example.com/v1alpha1",
					Kind:       "ExampleResource",
					Name:       "test-resource",
					UID:        types.UID("uid-456"),
				},
			},
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access-binding",
			Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "app.example.com/v1alpha1",
					Kind:       "ExampleResource",
					Name:       "test-resource",
					UID:        types.UID("uid-456"),
				},
			},
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "test-sa",
			Namespace: "operator-ns",
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-operator-scoped-access",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cr, role, rb).
		WithStatusSubresource(cr).
		Build()

	scoper := newTestRBACScoper(t, fakeClient, s)

	reconciler := &ExampleResourceReconciler{
		Client:     fakeClient,
		Scheme:     s,
		RBACScoper: scoper,
	}

	// Reconcile the deletion
	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-resource", Namespace: ns},
	})
	if err != nil {
		t.Fatalf("reconcile on deletion returned error: %v", err)
	}
	if result.Requeue || result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %+v", result)
	}

	// Verify Role was cleaned up (deleted since this was the only owner)
	cleanedRole := &rbacv1.Role{}
	err = fakeClient.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: ns,
	}, cleanedRole)
	if err == nil {
		t.Fatal("expected Role to be deleted after cleanup, but it still exists")
	}

	// Verify RoleBinding was cleaned up
	cleanedRB := &rbacv1.RoleBinding{}
	err = fakeClient.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: ns,
	}, cleanedRB)
	if err == nil {
		t.Fatal("expected RoleBinding to be deleted after cleanup, but it still exists")
	}

	// The fake client garbage-collects objects with a DeletionTimestamp and no
	// remaining finalizers, so the CR is already gone. Verify it was removed
	// (which implicitly proves the finalizer was stripped before the update).
	updatedCR := &appv1alpha1.ExampleResource{}
	err = fakeClient.Get(ctx, types.NamespacedName{
		Name: "test-resource", Namespace: ns,
	}, updatedCR)
	if err == nil {
		// If the CR still exists, the finalizer must have been removed
		for _, f := range updatedCR.Finalizers {
			if f == finalizerName {
				t.Fatal("expected finalizer to be removed, but it is still present")
			}
		}
	}
	// err != nil (NotFound) is the expected case: CR was GC'd after finalizer removal
}

func TestExampleResourceReconciler_NotFound(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		Build()

	scoper := newTestRBACScoper(t, fakeClient, s)

	reconciler := &ExampleResourceReconciler{
		Client:     fakeClient,
		Scheme:     s,
		RBACScoper: scoper,
	}

	// Reconcile a non-existent resource -- should return no error
	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("reconcile for non-existent resource returned error: %v", err)
	}
	if result.Requeue || result.RequeueAfter != 0 {
		t.Fatalf("expected no requeue, got %+v", result)
	}
}
