package rbacscope

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func newTestClusterScoper(t *testing.T, cl client.Client) *ClusterRBACScoper {
	t.Helper()
	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"nodes"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules failed: %v", err)
	}
	scoper, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewClusterRBACScoper failed: %v", err)
	}
	return scoper
}

func TestNewClusterRBACScoper_Validation(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	validRules, _ := NewAllowedRules(rbacv1.PolicyRule{Verbs: []string{"get"}})

	tests := []struct {
		name     string
		cl       client.Client
		identity OperatorIdentity
		allowed  AllowedRules
		errMsg   string
	}{
		{
			name: "nil client",
			cl:   nil,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "client must not be nil",
		},
		{
			name: "empty Name",
			cl:   cl,
			identity: OperatorIdentity{
				Name:           "",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.Name must not be empty",
		},
		{
			name: "empty ServiceAccount",
			cl:   cl,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.ServiceAccount must not be empty",
		},
		{
			name: "empty Namespace",
			cl:   cl,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.Namespace must not be empty",
		},
		{
			name: "empty AllowedRules",
			cl:   cl,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: AllowedRules{}, // zero-value: no rules and deferToStatic=false
			errMsg:  "AllowedRules must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClusterRBACScoper(tt.cl, tt.identity, tt.allowed)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestNewClusterRBACScoper_DNS1123Validation(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	validRules, _ := NewAllowedRules(rbacv1.PolicyRule{Verbs: []string{"get"}})

	tests := []struct {
		name     string
		identity OperatorIdentity
		wantErr  bool
		errMsg   string
	}{
		{
			name: "uppercase Name rejected",
			identity: OperatorIdentity{
				Name:           "My-Operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
		{
			name: "valid Name accepted",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: false,
		},
		{
			name: "Name with underscores rejected",
			identity: OperatorIdentity{
				Name:           "my_operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClusterRBACScoper(cl, tt.identity, validRules)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestClusterScoper_EnsureAccess_CreatesClusterRoleAndBinding(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify ClusterRole was created
	clusterRole := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole); err != nil {
		t.Fatalf("expected ClusterRole to exist, got error: %v", err)
	}

	// Verify ClusterRole rules
	if len(clusterRole.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(clusterRole.Rules))
	}
	policyRule := clusterRole.Rules[0]
	if len(policyRule.APIGroups) != 1 || policyRule.APIGroups[0] != "" {
		t.Errorf("expected APIGroups [\"\"], got %v", policyRule.APIGroups)
	}
	if len(policyRule.Resources) != 1 || policyRule.Resources[0] != "nodes" {
		t.Errorf("expected Resources [\"nodes\"], got %v", policyRule.Resources)
	}
	expectedVerbs := []string{"get", "list", "watch"}
	if len(policyRule.Verbs) != len(expectedVerbs) {
		t.Errorf("expected %d verbs, got %d", len(expectedVerbs), len(policyRule.Verbs))
	}
	for i, v := range expectedVerbs {
		if i < len(policyRule.Verbs) && policyRule.Verbs[i] != v {
			t.Errorf("expected verb[%d] = %q, got %q", i, v, policyRule.Verbs[i])
		}
	}

	// Verify ClusterRole labels
	if clusterRole.Labels["app.kubernetes.io/managed-by"] != "test-operator" {
		t.Errorf("expected managed-by label = test-operator, got %q", clusterRole.Labels["app.kubernetes.io/managed-by"])
	}
	if clusterRole.Labels["app.kubernetes.io/component"] != "cluster-rbac-scoper" {
		t.Errorf("expected component label = cluster-rbac-scoper, got %q", clusterRole.Labels["app.kubernetes.io/component"])
	}

	// Verify annotation-based ownership (NOT OwnerReferences)
	if len(clusterRole.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences on ClusterRole, got %d", len(clusterRole.OwnerReferences))
	}
	annotations := clusterRole.GetAnnotations()
	ownerAnnotation := annotations[ownerAnnotationKey]
	expectedKey := "target-ns/test-cr/test-uid-12345"
	if ownerAnnotation != expectedKey {
		t.Errorf("expected owner annotation %q, got %q", expectedKey, ownerAnnotation)
	}

	// Verify ClusterRoleBinding was created
	crb := &rbacv1.ClusterRoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb); err != nil {
		t.Fatalf("expected ClusterRoleBinding to exist, got error: %v", err)
	}

	// Verify ClusterRoleBinding RoleRef
	if crb.RoleRef.APIGroup != "rbac.authorization.k8s.io" {
		t.Errorf("expected RoleRef APIGroup = rbac.authorization.k8s.io, got %q", crb.RoleRef.APIGroup)
	}
	if crb.RoleRef.Kind != "ClusterRole" {
		t.Errorf("expected RoleRef Kind = ClusterRole, got %q", crb.RoleRef.Kind)
	}
	if crb.RoleRef.Name != "test-operator-cluster-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-cluster-scoped-access, got %q", crb.RoleRef.Name)
	}

	// Verify ClusterRoleBinding Subjects
	if len(crb.Subjects) != 1 {
		t.Fatalf("expected 1 Subject, got %d", len(crb.Subjects))
	}
	subj := crb.Subjects[0]
	if subj.Kind != "ServiceAccount" {
		t.Errorf("expected Subject Kind = ServiceAccount, got %q", subj.Kind)
	}
	if subj.Name != "test-operator-sa" {
		t.Errorf("expected Subject Name = test-operator-sa, got %q", subj.Name)
	}
	if subj.Namespace != "operator-system" {
		t.Errorf("expected Subject Namespace = operator-system, got %q", subj.Namespace)
	}

	// Verify ClusterRoleBinding labels
	if crb.Labels["app.kubernetes.io/managed-by"] != "test-operator" {
		t.Errorf("expected managed-by label = test-operator, got %q", crb.Labels["app.kubernetes.io/managed-by"])
	}
	if crb.Labels["app.kubernetes.io/component"] != "cluster-rbac-scoper" {
		t.Errorf("expected component label = cluster-rbac-scoper, got %q", crb.Labels["app.kubernetes.io/component"])
	}

	// Verify annotation-based ownership on ClusterRoleBinding
	if len(crb.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences on ClusterRoleBinding, got %d", len(crb.OwnerReferences))
	}
	crbAnnotation := crb.GetAnnotations()[ownerAnnotationKey]
	if crbAnnotation != expectedKey {
		t.Errorf("expected ClusterRoleBinding owner annotation %q, got %q", expectedKey, crbAnnotation)
	}
}

func TestClusterScoper_EnsureAccess_Idempotent(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	cr := newTestCR()
	ctx := context.Background()

	// First call
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("first EnsureAccess returned error: %v", err)
	}

	// Second call should not error
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("second EnsureAccess returned error: %v", err)
	}

	// Verify ClusterRole still exists with single annotation entry
	clusterRole := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole); err != nil {
		t.Fatalf("expected ClusterRole to exist after idempotent call, got error: %v", err)
	}

	ownerAnnotation := clusterRole.GetAnnotations()[ownerAnnotationKey]
	expectedKey := "target-ns/test-cr/test-uid-12345"
	if ownerAnnotation != expectedKey {
		t.Errorf("expected single owner annotation %q, got %q (possible duplication)", expectedKey, ownerAnnotation)
	}

	// Verify ClusterRoleBinding still exists
	crb := &rbacv1.ClusterRoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb); err != nil {
		t.Fatalf("expected ClusterRoleBinding to exist after idempotent call, got error: %v", err)
	}

	crbAnnotation := crb.GetAnnotations()[ownerAnnotationKey]
	if crbAnnotation != expectedKey {
		t.Errorf("expected single owner annotation on ClusterRoleBinding %q, got %q", expectedKey, crbAnnotation)
	}
}

func TestClusterScoper_EnsureAccess_MultiOwnerAnnotation(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	ctx := context.Background()

	// Two owners from different namespaces share the ClusterRole
	cr1 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-alpha",
			Namespace: "ns-alpha",
			UID:       types.UID("uid-alpha"),
		},
	}
	cr1.SetGroupVersionKind(testGVK)

	cr2 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-beta",
			Namespace: "ns-beta",
			UID:       types.UID("uid-beta"),
		},
	}
	cr2.SetGroupVersionKind(testGVK)

	// Ensure access for both
	if err := scoper.EnsureAccess(ctx, cr1); err != nil {
		t.Fatalf("EnsureAccess for cr1 failed: %v", err)
	}
	if err := scoper.EnsureAccess(ctx, cr2); err != nil {
		t.Fatalf("EnsureAccess for cr2 failed: %v", err)
	}

	// Verify both owners are in the annotation
	clusterRole := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole); err != nil {
		t.Fatalf("expected ClusterRole to exist: %v", err)
	}
	annotation := clusterRole.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(annotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected annotation to contain cr1's key, got %q", annotation)
	}
	if !strings.Contains(annotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected annotation to contain cr2's key, got %q", annotation)
	}

	// Verify ClusterRoleBinding also has both owners
	crb := &rbacv1.ClusterRoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb); err != nil {
		t.Fatalf("expected ClusterRoleBinding to exist: %v", err)
	}
	crbAnnotation := crb.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(crbAnnotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected ClusterRoleBinding annotation to contain cr1's key, got %q", crbAnnotation)
	}
	if !strings.Contains(crbAnnotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected ClusterRoleBinding annotation to contain cr2's key, got %q", crbAnnotation)
	}
}

func TestClusterScoper_CleanupAccess_DeletesWhenNoOwnersRemain(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	cr := newTestCR()
	ctx := context.Background()

	// First create
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Then cleanup
	if err := scoper.CleanupAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAccess returned error: %v", err)
	}

	// Verify ClusterRole is gone
	clusterRole := &rbacv1.ClusterRole{}
	err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole to be deleted, got err=%v", err)
	}

	// Verify ClusterRoleBinding is gone
	crb := &rbacv1.ClusterRoleBinding{}
	err = cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRoleBinding to be deleted, got err=%v", err)
	}
}

func TestClusterScoper_CleanupAccess_PreservesWhenOtherOwnersExist(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	ctx := context.Background()

	cr1 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-alpha",
			Namespace: "ns-alpha",
			UID:       types.UID("uid-alpha"),
		},
	}
	cr1.SetGroupVersionKind(testGVK)

	cr2 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-beta",
			Namespace: "ns-beta",
			UID:       types.UID("uid-beta"),
		},
	}
	cr2.SetGroupVersionKind(testGVK)

	// Ensure access for both
	if err := scoper.EnsureAccess(ctx, cr1); err != nil {
		t.Fatalf("EnsureAccess for cr1 failed: %v", err)
	}
	if err := scoper.EnsureAccess(ctx, cr2); err != nil {
		t.Fatalf("EnsureAccess for cr2 failed: %v", err)
	}

	// Cleanup cr1 only
	if err := scoper.CleanupAccess(ctx, cr1); err != nil {
		t.Fatalf("CleanupAccess for cr1 failed: %v", err)
	}

	// ClusterRole should still exist with cr2's annotation
	clusterRole := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole); err != nil {
		t.Fatal("ClusterRole was deleted when another owner (cr2) still exists")
	}
	remainingAnnotation := clusterRole.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(remainingAnnotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected remaining annotation to contain cr2's key, got %q", remainingAnnotation)
	}
	if strings.Contains(remainingAnnotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected cr1's key to be removed from annotation, got %q", remainingAnnotation)
	}

	// ClusterRoleBinding should also still exist
	crb := &rbacv1.ClusterRoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb); err != nil {
		t.Fatal("ClusterRoleBinding was deleted when another owner (cr2) still exists")
	}
	crbAnnotation := crb.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(crbAnnotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected remaining CRB annotation to contain cr2's key, got %q", crbAnnotation)
	}

	// Now cleanup cr2 -- everything should be deleted
	if err := scoper.CleanupAccess(ctx, cr2); err != nil {
		t.Fatalf("CleanupAccess for cr2 failed: %v", err)
	}

	err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole to be deleted after all owners cleaned up, got err=%v", err)
	}

	err = cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRoleBinding to be deleted after all owners cleaned up, got err=%v", err)
	}
}

func TestClusterScoper_CleanupAccess_NoErrorWhenNotFound(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)
	cr := newTestCR()
	ctx := context.Background()

	// Cleanup without creating anything should not error
	if err := scoper.CleanupAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAccess returned error when nothing existed: %v", err)
	}
}

func TestClusterScoper_EnsureAccess_AcceptsClusterScopedOwner_WithAnnotations(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	// No WithScheme — uses annotation-based ownership
	scoper := newTestClusterScoper(t, cl)
	ctx := context.Background()

	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	if err := scoper.EnsureAccess(ctx, clusterCR); err != nil {
		t.Fatalf("EnsureAccess should accept cluster-scoped owner, got: %v", err)
	}

	// Verify annotation-based ownership (no OwnerReferences without WithScheme)
	cr := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr); err != nil {
		t.Fatalf("expected ClusterRole to exist: %v", err)
	}
	if len(cr.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences without WithScheme, got %d", len(cr.OwnerReferences))
	}
	annotation := cr.GetAnnotations()[ownerAnnotationKey]
	expectedKey := "/cluster-scoped-cr/cluster-uid"
	if annotation != expectedKey {
		t.Errorf("expected owner annotation %q, got %q", expectedKey, annotation)
	}

	// CleanupAccess should also work
	if err := scoper.CleanupAccess(ctx, clusterCR); err != nil {
		t.Fatalf("CleanupAccess should accept cluster-scoped owner, got: %v", err)
	}

	err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole to be deleted, got err=%v", err)
	}
}

func TestClusterScoper_EnsureAccess_ClusterScopedOwner_WithScheme_UsesOwnerReferences(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"nodes"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules failed: %v", err)
	}

	scoper, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
		WithScheme(s),
	)
	if err != nil {
		t.Fatalf("NewClusterRBACScoper failed: %v", err)
	}
	ctx := context.Background()

	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	if err := scoper.EnsureAccess(ctx, clusterCR); err != nil {
		t.Fatalf("EnsureAccess should accept cluster-scoped owner with WithScheme, got: %v", err)
	}

	// Verify OwnerReference-based ownership (cluster→cluster is allowed)
	cr := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr); err != nil {
		t.Fatalf("expected ClusterRole to exist: %v", err)
	}
	if len(cr.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference with WithScheme, got %d", len(cr.OwnerReferences))
	}
	if cr.OwnerReferences[0].Name != "cluster-scoped-cr" {
		t.Errorf("expected OwnerReference Name = cluster-scoped-cr, got %q", cr.OwnerReferences[0].Name)
	}

	// Verify no annotation-based ownership (OwnerReferences are used instead)
	annotation := cr.GetAnnotations()[ownerAnnotationKey]
	if annotation != "" {
		t.Errorf("expected no owner annotation when using OwnerReferences, got %q", annotation)
	}

	// CleanupAccess should remove OwnerReference
	if err := scoper.CleanupAccess(ctx, clusterCR); err != nil {
		t.Fatalf("CleanupAccess failed: %v", err)
	}

	err = cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole to be deleted, got err=%v", err)
	}
}

func TestClusterScoper_EnsureAccess_NamespaceScopedOwner_WithScheme_UsesAnnotations(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"nodes"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules failed: %v", err)
	}

	scoper, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
		WithScheme(s),
	)
	if err != nil {
		t.Fatalf("NewClusterRBACScoper failed: %v", err)
	}
	ctx := context.Background()

	// Namespace-scoped owner — even with WithScheme, K8s rejects
	// OwnerReferences from namespace-scoped to cluster-scoped
	nsCR := newTestCR()

	if err := scoper.EnsureAccess(ctx, nsCR); err != nil {
		t.Fatalf("EnsureAccess should accept namespace-scoped owner, got: %v", err)
	}

	// Verify annotation-based ownership (namespace→cluster cannot use OwnerReferences)
	cr := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr); err != nil {
		t.Fatalf("expected ClusterRole to exist: %v", err)
	}
	if len(cr.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences for namespace-scoped owner, got %d", len(cr.OwnerReferences))
	}
	annotation := cr.GetAnnotations()[ownerAnnotationKey]
	if annotation == "" {
		t.Error("expected owner annotation for namespace-scoped owner, got empty")
	}
}

func TestClusterScoper_EnsureAccess_ClusterRoleBindingDriftRecovery(t *testing.T) {
	s := testScheme()

	// Pre-create a ClusterRoleBinding with a DIFFERENT RoleRef to simulate drift.
	driftedCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access-binding",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "some-other-cluster-role", // wrong RoleRef
		},
		Subjects: []rbacv1.Subject{{
			Kind: "ServiceAccount",
			Name: "old-sa",
		}},
	}

	// Use an interceptor to return IsInvalid on the first ClusterRoleBinding Update,
	// simulating Kubernetes rejecting a RoleRef change.
	var updateRejected atomic.Bool
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(driftedCRB).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if crb, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
					if crb.Name == "test-operator-cluster-scoped-access-binding" && !updateRejected.Load() {
						updateRejected.Store(true)
						return apierrors.NewInvalid(
							rbacv1.SchemeGroupVersion.WithKind("ClusterRoleBinding").GroupKind(),
							crb.Name,
							nil,
						)
					}
				}
				return cl.Update(ctx, obj, opts...)
			},
		}).Build()

	scoper := newTestClusterScoper(t, cl)
	cr := newTestCR()
	ctx := context.Background()

	// EnsureAccess should succeed by detecting the invalid error and recreating.
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess should recover from ClusterRoleBinding drift, got error: %v", err)
	}

	// Verify the ClusterRoleBinding now has the correct RoleRef.
	crb := &rbacv1.ClusterRoleBinding{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access-binding",
	}, crb); err != nil {
		t.Fatalf("expected ClusterRoleBinding to exist after drift recovery: %v", err)
	}

	if crb.RoleRef.Name != "test-operator-cluster-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-cluster-scoped-access, got %q", crb.RoleRef.Name)
	}
	if crb.Subjects[0].Name != "test-operator-sa" {
		t.Errorf("expected Subject Name = test-operator-sa, got %q", crb.Subjects[0].Name)
	}

	// Verify the interceptor was triggered (the drift path was actually exercised).
	if !updateRejected.Load() {
		t.Error("expected the interceptor to reject at least one Update, but it was never triggered")
	}
}

func TestClusterScoper_EnsureAccess_DeferToStaticRBACProducesEmptyClusterRole(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	allowed := DeferToStaticRBAC()
	scoper, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewClusterRBACScoper failed: %v", err)
	}

	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify ClusterRole has zero rules when DeferToStaticRBAC is used
	clusterRole := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-cluster-scoped-access",
	}, clusterRole); err != nil {
		t.Fatalf("expected ClusterRole to exist, got error: %v", err)
	}

	if len(clusterRole.Rules) != 0 {
		t.Errorf("expected 0 rules with DeferToStaticRBAC, got %d", len(clusterRole.Rules))
	}
}

// --- ClusterRBACScoper GarbageCollectOrphanedOwners Tests ---

func TestClusterGarbageCollectOrphanedOwners_RemovesStaleEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Pre-create ClusterRole and ClusterRoleBinding with stale annotation entries
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
			},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access-binding",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "test-operator-cluster-scoped-access",
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, crb).Build()
	scoper := newTestClusterScoper(t, cl)

	resolver := newTestResolver(map[string]bool{})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.ResourcesScanned != 2 {
		t.Errorf("expected 2 resources scanned, got %d", result.ResourcesScanned)
	}
	if result.EntriesRemoved != 2 {
		t.Errorf("expected 2 entries removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 2 {
		t.Errorf("expected 2 resources deleted, got %d", result.ResourcesDeleted)
	}

	// Verify ClusterRole is deleted
	gotCR := &rbacv1.ClusterRole{}
	crErr := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR)
	if !apierrors.IsNotFound(crErr) {
		t.Errorf("expected ClusterRole to be deleted, got err=%v", crErr)
	}

	// Verify ClusterRoleBinding is deleted
	gotCRB := &rbacv1.ClusterRoleBinding{}
	crbErr := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access-binding"}, gotCRB)
	if !apierrors.IsNotFound(crbErr) {
		t.Errorf("expected ClusterRoleBinding to be deleted, got err=%v", crbErr)
	}
}

func TestClusterGarbageCollectOrphanedOwners_PreservesValidEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "valid-ns/valid-cr/valid-uid",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoper(t, cl)

	resolver := newTestResolver(map[string]bool{
		"valid-ns/valid-cr/valid-uid": true,
	})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 0 {
		t.Errorf("expected 0 entries removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted, got %d", result.ResourcesDeleted)
	}

	gotCR := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR); err != nil {
		t.Fatalf("expected ClusterRole to still exist: %v", err)
	}
	annotation := gotCR.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation preserved as %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
}

func TestClusterGarbageCollectOrphanedOwners_MixedEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "valid-ns/valid-cr/valid-uid,stale-ns/stale-cr/stale-uid",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoper(t, cl)

	resolver := newTestResolver(map[string]bool{
		"valid-ns/valid-cr/valid-uid": true,
	})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 1 {
		t.Errorf("expected 1 entry removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted, got %d", result.ResourcesDeleted)
	}

	gotCR := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR); err != nil {
		t.Fatalf("expected ClusterRole to still exist: %v", err)
	}
	annotation := gotCR.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation to be %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
}

func TestClusterGarbageCollectOrphanedOwners_RemovesMalformedEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "bad,ns/name,valid-ns/valid-cr/valid-uid",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoper(t, cl)

	resolver := newTestResolver(map[string]bool{
		"valid-ns/valid-cr/valid-uid": true,
	})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 2 {
		t.Errorf("expected 2 malformed entries removed, got %d", result.EntriesRemoved)
	}

	gotCR := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR); err != nil {
		t.Fatalf("expected ClusterRole to still exist: %v", err)
	}
	annotation := gotCR.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation to be %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
}

func TestClusterGarbageCollectOrphanedOwners_ClusterScopedOwnerEntry(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Cluster-scoped owner produces annotation with empty namespace: "/name/uid"
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "/cluster-cr/cluster-uid,ns-a/ns-cr/ns-uid",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoper(t, cl)

	// Only the namespace-scoped owner exists; cluster-scoped one is orphaned
	resolver := newTestResolver(map[string]bool{
		"ns-a/ns-cr/ns-uid": true,
	})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 1 {
		t.Errorf("expected 1 entry removed, got %d", result.EntriesRemoved)
	}

	gotCR := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR); err != nil {
		t.Fatalf("expected ClusterRole to still exist: %v", err)
	}
	annotation := gotCR.GetAnnotations()[ownerAnnotationKey]
	if annotation != "ns-a/ns-cr/ns-uid" {
		t.Errorf("expected annotation to be %q, got %q", "ns-a/ns-cr/ns-uid", annotation)
	}
}

func TestClusterGarbageCollectOrphanedOwners_NotFoundNoError(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)

	resolver := newTestResolver(map[string]bool{})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.ResourcesScanned != 0 {
		t.Errorf("expected 0 resources scanned, got %d", result.ResourcesScanned)
	}
	if result.EntriesRemoved != 0 {
		t.Errorf("expected 0 entries removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted, got %d", result.ResourcesDeleted)
	}
}

func newTestClusterScoperWithScheme(t *testing.T, cl client.Client, s *runtime.Scheme) *ClusterRBACScoper {
	t.Helper()
	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"nodes"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules failed: %v", err)
	}
	scoper, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
		WithScheme(s),
	)
	if err != nil {
		t.Fatalf("NewClusterRBACScoper with WithScheme failed: %v", err)
	}
	return scoper
}

func TestClusterGC_WithScheme_PreservesResourceWithOwnerRefs(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Pre-create a ClusterRole with both an OwnerReference and a stale annotation.
	// GC should remove the stale annotation but NOT delete the resource because
	// the OwnerReference is still present.
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "test.example.com/v1alpha1",
				Kind:       "TestResource",
				Name:       "valid-owner",
				UID:        types.UID("valid-uid"),
			}},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoperWithScheme(t, cl, s)

	resolver := newTestResolver(map[string]bool{})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 1 {
		t.Errorf("expected 1 entry removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted (OwnerRef still present), got %d", result.ResourcesDeleted)
	}

	// Verify ClusterRole still exists
	gotCR := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR); err != nil {
		t.Fatalf("expected ClusterRole to still exist: %v", err)
	}
	if len(gotCR.OwnerReferences) != 1 {
		t.Errorf("expected OwnerReference preserved, got %d", len(gotCR.OwnerReferences))
	}
}

func TestClusterGC_WithScheme_DeletesWhenNoOwnerRefsRemain(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// ClusterRole with stale annotation AND no OwnerReferences.
	// With WithScheme, GC checks both — should delete.
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-operator-cluster-scoped-access",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "cluster-rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cr).Build()
	scoper := newTestClusterScoperWithScheme(t, cl, s)

	resolver := newTestResolver(map[string]bool{})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.EntriesRemoved != 1 {
		t.Errorf("expected 1 entry removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 1 {
		t.Errorf("expected 1 resource deleted, got %d", result.ResourcesDeleted)
	}

	gotCR := &rbacv1.ClusterRole{}
	err = cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, gotCR)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole to be deleted, got err=%v", err)
	}
}

func TestClusterScoper_MixedOwnership_WithScheme(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoperWithScheme(t, cl, s)
	ctx := context.Background()

	// Cluster-scoped owner (gets OwnerReference via WithScheme)
	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-owner",
			UID:  types.UID("cluster-owner-uid"),
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	// Namespace-scoped owner (gets annotation even with WithScheme)
	nsCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns-owner",
			Namespace: "ns-a",
			UID:       types.UID("ns-owner-uid"),
		},
	}
	nsCR.SetGroupVersionKind(testGVK)

	// Both owners ensure access
	if err := scoper.EnsureAccess(ctx, clusterCR); err != nil {
		t.Fatalf("EnsureAccess for cluster-scoped owner failed: %v", err)
	}
	if err := scoper.EnsureAccess(ctx, nsCR); err != nil {
		t.Fatalf("EnsureAccess for namespace-scoped owner failed: %v", err)
	}

	// Verify both ownership mechanisms are present
	cr := &rbacv1.ClusterRole{}
	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr); err != nil {
		t.Fatalf("expected ClusterRole to exist: %v", err)
	}
	if len(cr.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference from cluster-scoped owner, got %d", len(cr.OwnerReferences))
	}
	annotation := cr.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(annotation, "ns-a/ns-owner/ns-owner-uid") {
		t.Errorf("expected annotation from namespace-scoped owner, got %q", annotation)
	}

	// Clean up cluster-scoped owner — resource should survive (ns-owner still present)
	if err := scoper.CleanupAccess(ctx, clusterCR); err != nil {
		t.Fatalf("CleanupAccess for cluster-scoped owner failed: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr); err != nil {
		t.Fatal("ClusterRole was deleted when namespace-scoped owner still exists")
	}
	if len(cr.OwnerReferences) != 0 {
		t.Errorf("expected OwnerReference removed, got %d", len(cr.OwnerReferences))
	}
	remainingAnnotation := cr.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(remainingAnnotation, "ns-a/ns-owner/ns-owner-uid") {
		t.Errorf("expected ns-owner annotation preserved, got %q", remainingAnnotation)
	}

	// Clean up namespace-scoped owner — resource should be deleted
	if err := scoper.CleanupAccess(ctx, nsCR); err != nil {
		t.Fatalf("CleanupAccess for namespace-scoped owner failed: %v", err)
	}

	err := cl.Get(ctx, types.NamespacedName{Name: "test-operator-cluster-scoped-access"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected ClusterRole deleted after all owners cleaned up, got err=%v", err)
	}
}

func TestNewClusterRBACScoper_WithSchemeNil_ReturnsError(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	validRules, _ := NewAllowedRules(rbacv1.PolicyRule{Verbs: []string{"get"}})

	_, err := NewClusterRBACScoper(
		cl,
		OperatorIdentity{
			Name:           "test",
			ServiceAccount: "test-sa",
			Namespace:      "test-ns",
		},
		validRules,
		WithScheme(nil),
	)
	if err == nil {
		t.Fatal("expected error for WithScheme(nil), got nil")
	}
	if !strings.Contains(err.Error(), "WithScheme requires a non-nil scheme") {
		t.Errorf("expected error about non-nil scheme, got %q", err.Error())
	}
}

func TestClusterRBACScoper_ManagedLabels(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)

	labels := scoper.ManagedLabels()

	if got := labels["app.kubernetes.io/managed-by"]; got != "test-operator" {
		t.Errorf("expected managed-by label 'test-operator', got %q", got)
	}
	if got := labels["app.kubernetes.io/component"]; got != "cluster-rbac-scoper" {
		t.Errorf("expected component label 'cluster-rbac-scoper', got %q", got)
	}
	if len(labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(labels))
	}

	// Verify returned map is a fresh copy (mutations don't affect scoper)
	labels["extra"] = "value"
	labels2 := scoper.ManagedLabels()
	if len(labels2) != 2 {
		t.Errorf("expected 2 labels after mutation of previous copy, got %d", len(labels2))
	}
}

func TestClusterRBACScoper_ClusterRoleName(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)

	if got := scoper.ClusterRoleName(); got != "test-operator-cluster-scoped-access" {
		t.Errorf("expected 'test-operator-cluster-scoped-access', got %q", got)
	}
}

func TestClusterRBACScoper_ClusterRoleBindingName(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	scoper := newTestClusterScoper(t, cl)

	if got := scoper.ClusterRoleBindingName(); got != "test-operator-cluster-scoped-access-binding" {
		t.Errorf("expected 'test-operator-cluster-scoped-access-binding', got %q", got)
	}
}
