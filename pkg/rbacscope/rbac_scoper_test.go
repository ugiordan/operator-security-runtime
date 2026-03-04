package rbacscope

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// testResource implements client.Object for testing without CRD dependency.
type testResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
}

func (t *testResource) DeepCopyObject() runtime.Object {
	return &testResource{TypeMeta: t.TypeMeta, ObjectMeta: *t.ObjectMeta.DeepCopy()}
}

var testGVK = schema.GroupVersionKind{
	Group:   "test.example.com",
	Version: "v1alpha1",
	Kind:    "TestResource",
}

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	s.AddKnownTypeWithName(testGVK, &testResource{})
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: testGVK.Group, Version: testGVK.Version, Kind: testGVK.Kind + "List"},
		&metav1.List{},
	)
	return s
}

func newTestScoper(t *testing.T, s *runtime.Scheme, cl *fake.ClientBuilder) *RBACScoper {
	t.Helper()
	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules failed: %v", err)
	}
	scoper, err := NewRBACScoper(
		cl.Build(),
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper failed: %v", err)
	}
	return scoper
}

func newTestCR() *testResource {
	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cr",
			Namespace: "target-ns",
			UID:       types.UID("test-uid-12345"),
		},
	}
	cr.SetGroupVersionKind(testGVK)
	return cr
}

func TestEnsureAccess_CreatesRoleAndRoleBinding(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify Role was created
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist, got error: %v", err)
	}

	// Verify Role rules
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	policyRule := role.Rules[0]
	if len(policyRule.APIGroups) != 1 || policyRule.APIGroups[0] != "" {
		t.Errorf("expected APIGroups [\"\"], got %v", policyRule.APIGroups)
	}
	if len(policyRule.Resources) != 1 || policyRule.Resources[0] != "secrets" {
		t.Errorf("expected Resources [\"secrets\"], got %v", policyRule.Resources)
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

	// Verify Role labels
	if role.Labels["app.kubernetes.io/managed-by"] != "test-operator" {
		t.Errorf("expected managed-by label = test-operator, got %q", role.Labels["app.kubernetes.io/managed-by"])
	}
	if role.Labels["app.kubernetes.io/component"] != "rbac-scoper" {
		t.Errorf("expected component label = rbac-scoper, got %q", role.Labels["app.kubernetes.io/component"])
	}

	// Verify OwnerReference on Role
	if len(role.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference, got %d", len(role.OwnerReferences))
	}
	ownerRef := role.OwnerReferences[0]
	if ownerRef.APIVersion != "test.example.com/v1alpha1" {
		t.Errorf("expected OwnerReference APIVersion = test.example.com/v1alpha1, got %q", ownerRef.APIVersion)
	}
	if ownerRef.Kind != "TestResource" {
		t.Errorf("expected OwnerReference Kind = TestResource, got %q", ownerRef.Kind)
	}
	if ownerRef.Name != "test-cr" {
		t.Errorf("expected OwnerReference Name = test-cr, got %q", ownerRef.Name)
	}
	if ownerRef.UID != types.UID("test-uid-12345") {
		t.Errorf("expected OwnerReference UID = test-uid-12345, got %q", ownerRef.UID)
	}

	// Verify RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist, got error: %v", err)
	}

	// Verify RoleBinding RoleRef
	if rb.RoleRef.APIGroup != "rbac.authorization.k8s.io" {
		t.Errorf("expected RoleRef APIGroup = rbac.authorization.k8s.io, got %q", rb.RoleRef.APIGroup)
	}
	if rb.RoleRef.Kind != "Role" {
		t.Errorf("expected RoleRef Kind = Role, got %q", rb.RoleRef.Kind)
	}
	if rb.RoleRef.Name != "test-operator-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-scoped-access, got %q", rb.RoleRef.Name)
	}

	// Verify RoleBinding Subjects
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 Subject, got %d", len(rb.Subjects))
	}
	subj := rb.Subjects[0]
	if subj.Kind != "ServiceAccount" {
		t.Errorf("expected Subject Kind = ServiceAccount, got %q", subj.Kind)
	}
	if subj.Name != "test-operator-sa" {
		t.Errorf("expected Subject Name = test-operator-sa, got %q", subj.Name)
	}
	if subj.Namespace != "operator-system" {
		t.Errorf("expected Subject Namespace = operator-system, got %q", subj.Namespace)
	}

	// Verify RoleBinding labels
	if rb.Labels["app.kubernetes.io/managed-by"] != "test-operator" {
		t.Errorf("expected managed-by label = test-operator, got %q", rb.Labels["app.kubernetes.io/managed-by"])
	}
	if rb.Labels["app.kubernetes.io/component"] != "rbac-scoper" {
		t.Errorf("expected component label = rbac-scoper, got %q", rb.Labels["app.kubernetes.io/component"])
	}

	// Verify OwnerReference on RoleBinding
	if len(rb.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference on RoleBinding, got %d", len(rb.OwnerReferences))
	}
	rbOwnerRef := rb.OwnerReferences[0]
	if rbOwnerRef.Name != "test-cr" {
		t.Errorf("expected RoleBinding OwnerReference Name = test-cr, got %q", rbOwnerRef.Name)
	}
	if rbOwnerRef.APIVersion != "test.example.com/v1alpha1" {
		t.Errorf("expected RoleBinding OwnerReference APIVersion = test.example.com/v1alpha1, got %q", rbOwnerRef.APIVersion)
	}
	if rbOwnerRef.Kind != "TestResource" {
		t.Errorf("expected RoleBinding OwnerReference Kind = TestResource, got %q", rbOwnerRef.Kind)
	}
}

func TestEnsureAccess_Idempotent(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
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

	// Verify Role still exists
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist after idempotent call, got error: %v", err)
	}

	// Verify RoleBinding still exists
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist after idempotent call, got error: %v", err)
	}
}

func TestEnsureAccess_CustomRules(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)

	allowed, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "create", "update"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules returned error: %v", err)
	}

	scoper, err := NewRBACScoper(
		builder.Build(),
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper returned error: %v", err)
	}

	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist, got error: %v", err)
	}

	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	policyRule := role.Rules[0]
	expectedVerbs := []string{"get", "create", "update"}
	if len(policyRule.Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d", len(expectedVerbs), len(policyRule.Verbs))
	}
	for i, v := range expectedVerbs {
		if policyRule.Verbs[i] != v {
			t.Errorf("expected verb[%d] = %q, got %q", i, v, policyRule.Verbs[i])
		}
	}
}

func TestCleanupAccess_DeletesRoleAndRoleBinding(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
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

	// Verify Role is gone
	role := &rbacv1.Role{}
	err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role)
	if err == nil {
		t.Fatal("expected Role to be deleted, but it still exists")
	}

	// Verify RoleBinding is gone
	rb := &rbacv1.RoleBinding{}
	err = scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb)
	if err == nil {
		t.Fatal("expected RoleBinding to be deleted, but it still exists")
	}
}

func TestCleanupAccess_NoErrorWhenAlreadyGone(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	cr := newTestCR()
	ctx := context.Background()

	// Cleanup without creating anything should not error
	if err := scoper.CleanupAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAccess returned error when nothing existed: %v", err)
	}
}

func TestMultipleCRsInSameNamespace(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr1 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-one",
			Namespace: "shared-ns",
			UID:       types.UID("uid-cr1"),
		},
	}
	cr1.SetGroupVersionKind(testGVK)

	cr2 := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cr-two",
			Namespace: "shared-ns",
			UID:       types.UID("uid-cr2"),
		},
	}
	cr2.SetGroupVersionKind(testGVK)

	// Ensure access for both CRs
	if err := scoper.EnsureAccess(ctx, cr1); err != nil {
		t.Fatalf("EnsureAccess for cr1 failed: %v", err)
	}
	if err := scoper.EnsureAccess(ctx, cr2); err != nil {
		t.Fatalf("EnsureAccess for cr2 failed: %v", err)
	}

	// Verify Role has TWO OwnerReferences
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	if len(role.OwnerReferences) != 2 {
		t.Fatalf("expected 2 OwnerReferences, got %d", len(role.OwnerReferences))
	}

	// Cleanup cr1 -- Role should survive (cr2 still owns it)
	if err := scoper.CleanupAccess(ctx, cr1); err != nil {
		t.Fatalf("CleanupAccess for cr1 failed: %v", err)
	}

	// Verify Role still exists with 1 OwnerReference
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-ns",
	}, role); err != nil {
		t.Fatal("Role was deleted when another CR still owns it")
	}
	if len(role.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference after cr1 cleanup, got %d", len(role.OwnerReferences))
	}
	if role.OwnerReferences[0].Name != "cr-two" {
		t.Errorf("expected remaining owner to be cr-two, got %q", role.OwnerReferences[0].Name)
	}

	// Cleanup cr2 -- now Role should be deleted
	if err := scoper.CleanupAccess(ctx, cr2); err != nil {
		t.Fatalf("CleanupAccess for cr2 failed: %v", err)
	}

	err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-ns",
	}, role)
	if err == nil {
		t.Fatal("expected Role to be deleted after all owners cleaned up")
	}
}

func TestEnsureAccess_MultiResourceRules(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)

	allowed, err := NewAllowedRules(
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"},
		},
	)
	if err != nil {
		t.Fatalf("NewAllowedRules returned error: %v", err)
	}

	scoper, err := NewRBACScoper(
		builder.Build(),
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper returned error: %v", err)
	}

	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify Role was created with both rules
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist, got error: %v", err)
	}

	if len(role.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(role.Rules))
	}

	// Verify first rule (secrets)
	if len(role.Rules[0].Resources) != 1 || role.Rules[0].Resources[0] != "secrets" {
		t.Errorf("expected first rule Resources [\"secrets\"], got %v", role.Rules[0].Resources)
	}
	expectedVerbs := []string{"get", "list", "watch"}
	if len(role.Rules[0].Verbs) != len(expectedVerbs) {
		t.Errorf("expected %d verbs in first rule, got %d", len(expectedVerbs), len(role.Rules[0].Verbs))
	}
	for i, v := range expectedVerbs {
		if i < len(role.Rules[0].Verbs) && role.Rules[0].Verbs[i] != v {
			t.Errorf("expected first rule verb[%d] = %q, got %q", i, v, role.Rules[0].Verbs[i])
		}
	}

	// Verify second rule (configmaps)
	if len(role.Rules[1].Resources) != 1 || role.Rules[1].Resources[0] != "configmaps" {
		t.Errorf("expected second rule Resources [\"configmaps\"], got %v", role.Rules[1].Resources)
	}
	expectedVerbs2 := []string{"get", "list"}
	if len(role.Rules[1].Verbs) != len(expectedVerbs2) {
		t.Errorf("expected %d verbs in second rule, got %d", len(expectedVerbs2), len(role.Rules[1].Verbs))
	}
	for i, v := range expectedVerbs2 {
		if i < len(role.Rules[1].Verbs) && role.Rules[1].Verbs[i] != v {
			t.Errorf("expected second rule verb[%d] = %q, got %q", i, v, role.Rules[1].Verbs[i])
		}
	}

	// Verify RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist, got error: %v", err)
	}

	// Verify RoleBinding references the correct Role
	if rb.RoleRef.Name != "test-operator-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-scoped-access, got %q", rb.RoleRef.Name)
	}
}

func TestEnsureAccess_RuleUpdateConvergence(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	cl := builder.Build()

	// First scoper: secrets only
	allowed1, err := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "list", "watch"},
	})
	if err != nil {
		t.Fatalf("NewAllowedRules returned error: %v", err)
	}

	scoper1, err := NewRBACScoper(
		cl,
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed1,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper returned error: %v", err)
	}

	cr := newTestCR()
	ctx := context.Background()

	// First call: secrets only
	if err := scoper1.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("first EnsureAccess returned error: %v", err)
	}

	role := &rbacv1.Role{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule after first call, got %d", len(role.Rules))
	}

	// Second scoper: secrets + configmaps (simulates configuration change)
	allowed2, err := NewAllowedRules(
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"},
		},
	)
	if err != nil {
		t.Fatalf("NewAllowedRules returned error: %v", err)
	}

	scoper2, err := NewRBACScoper(
		cl,
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		allowed2,
	)
	if err != nil {
		t.Fatalf("NewRBACScoper returned error: %v", err)
	}

	// Second call: should update the Role with 2 rules
	if err := scoper2.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("second EnsureAccess returned error: %v", err)
	}

	if err := cl.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist after update: %v", err)
	}
	if len(role.Rules) != 2 {
		t.Fatalf("expected 2 rules after update, got %d", len(role.Rules))
	}
	if role.Rules[1].Resources[0] != "configmaps" {
		t.Errorf("expected second rule for configmaps, got %v", role.Rules[1].Resources)
	}
}

func TestNewRBACScoper_ValidationErrors(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	cl := builder.Build()

	validRules, _ := NewAllowedRules(rbacv1.PolicyRule{Verbs: []string{"get"}})

	tests := []struct {
		name     string
		cl       client.Client
		scheme   *runtime.Scheme
		identity OperatorIdentity
		allowed  AllowedRules
		errMsg   string
	}{
		{
			name:   "nil client",
			cl:     nil,
			scheme: s,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "client must not be nil",
		},
		{
			name:   "nil scheme",
			cl:     cl,
			scheme: nil,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "scheme must not be nil",
		},
		{
			name:   "empty Name",
			cl:     cl,
			scheme: s,
			identity: OperatorIdentity{
				Name:           "",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.Name must not be empty",
		},
		{
			name:   "empty ServiceAccount",
			cl:     cl,
			scheme: s,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "",
				Namespace:      "test-ns",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.ServiceAccount must not be empty",
		},
		{
			name:   "empty Namespace",
			cl:     cl,
			scheme: s,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "",
			},
			allowed: validRules,
			errMsg:  "OperatorIdentity.Namespace must not be empty",
		},
		{
			name:   "empty AllowedRules",
			cl:     cl,
			scheme: s,
			identity: OperatorIdentity{
				Name:           "test",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			allowed: AllowedRules{}, // zero-value: no rules and allowAll=false
			errMsg:  "AllowedRules must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRBACScoper(tt.cl, tt.scheme, tt.identity, tt.allowed)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestNewRBACScoper_DNS1123Validation(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	validRules, _ := NewAllowedRules(rbacv1.PolicyRule{Verbs: []string{"get"}})

	longName := strings.Repeat("a", 254)

	tests := []struct {
		name     string
		identity OperatorIdentity
		wantErr  bool
		errMsg   string
	}{
		{
			name: "uppercase Name",
			identity: OperatorIdentity{
				Name:           "My-Operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
		{
			name: "Name with underscores",
			identity: OperatorIdentity{
				Name:           "my_operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
		{
			name: "Name with spaces",
			identity: OperatorIdentity{
				Name:           "my operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
		{
			name: "Name too long",
			identity: OperatorIdentity{
				Name:           longName,
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be no more than 253 characters",
		},
		{
			name: "Name starting with hyphen",
			identity: OperatorIdentity{
				Name:           "-my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Name must be a valid DNS-1123 subdomain",
		},
		{
			name: "valid Name",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: false,
		},
		{
			name: "valid Name with dots",
			identity: OperatorIdentity{
				Name:           "my.operator.v1",
				ServiceAccount: "test-sa",
				Namespace:      "test-ns",
			},
			wantErr: false,
		},
		{
			name: "uppercase ServiceAccount",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "My-SA",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.ServiceAccount must be a valid DNS-1123 subdomain",
		},
		{
			name: "ServiceAccount with underscores",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "my_sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.ServiceAccount must be a valid DNS-1123 subdomain",
		},
		{
			name: "ServiceAccount starting with hyphen",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "-my-sa",
				Namespace:      "test-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.ServiceAccount must be a valid DNS-1123 subdomain",
		},
		{
			name: "uppercase Namespace",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "My-Namespace",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Namespace must be a valid DNS-1123 subdomain",
		},
		{
			name: "Namespace with underscores",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "my_namespace",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Namespace must be a valid DNS-1123 subdomain",
		},
		{
			name: "Namespace starting with hyphen",
			identity: OperatorIdentity{
				Name:           "my-operator",
				ServiceAccount: "test-sa",
				Namespace:      "-my-ns",
			},
			wantErr: true,
			errMsg:  "OperatorIdentity.Namespace must be a valid DNS-1123 subdomain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRBACScoper(cl, s, tt.identity, validRules)
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

func TestNewAllowedRules_EmptyReturnsError(t *testing.T) {
	_, err := NewAllowedRules()
	if err == nil {
		t.Fatal("expected error for empty NewAllowedRules, got nil")
	}
	if !strings.Contains(err.Error(), "at least one PolicyRule") {
		t.Errorf("expected error about PolicyRule, got %q", err.Error())
	}
}

func TestNewAllowedRules_DefensiveCopy(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get"},
	}
	allowed, err := NewAllowedRules(rule)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the original rule
	rule.Verbs = append(rule.Verbs, "*")
	// Verify the AllowedRules was not affected
	if len(allowed.rules[0].Verbs) != 1 || allowed.rules[0].Verbs[0] != "get" {
		t.Errorf("AllowedRules was mutated: got verbs %v", allowed.rules[0].Verbs)
	}
}

func TestNewRBACScoper_WithOptions(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	allowed, _ := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
	})

	scoper, err := NewRBACScoper(cl, s,
		OperatorIdentity{Name: "op", ServiceAccount: "sa", Namespace: "ns"},
		allowed,
		WithDeniedNamespaces("custom-ns"),
		WithAggregationLabelCheck(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoper.config.deniedNamespaces) != 1 || scoper.config.deniedNamespaces[0] != "custom-ns" {
		t.Errorf("expected deniedNamespaces = [custom-ns], got %v", scoper.config.deniedNamespaces)
	}
	if !scoper.config.aggregationLabelCheck {
		t.Error("expected aggregationLabelCheck = true")
	}
}

func TestEnsureAccess_RejectsClusterScopedOwner(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Create a cluster-scoped resource (no namespace)
	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
			// No Namespace -- cluster-scoped
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	err := scoper.EnsureAccess(ctx, clusterCR)
	if err == nil {
		t.Fatal("expected error for cluster-scoped owner, got nil")
	}
	if !strings.Contains(err.Error(), "namespace-scoped") {
		t.Errorf("expected error about namespace-scoped, got %q", err.Error())
	}

	// CleanupAccess should also reject
	err = scoper.CleanupAccess(ctx, clusterCR)
	if err == nil {
		t.Fatal("expected error from CleanupAccess for cluster-scoped owner, got nil")
	}
	if !strings.Contains(err.Error(), "namespace-scoped") {
		t.Errorf("CleanupAccess: expected error about namespace-scoped, got %q", err.Error())
	}
}

func TestEnsureAccess_RoleBindingDriftRecovery(t *testing.T) {
	s := testScheme()

	// Pre-create a RoleBinding with a DIFFERENT RoleRef to simulate drift.
	driftedRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access-binding",
			Namespace: "target-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "some-other-role", // wrong RoleRef
		},
		Subjects: []rbacv1.Subject{{
			Kind: "ServiceAccount",
			Name: "old-sa",
		}},
	}

	// Use an interceptor to return IsInvalid on the first RoleBinding Update,
	// simulating Kubernetes rejecting a RoleRef change. After the first rejection,
	// allow subsequent operations so the delete-and-recreate path works.
	var updateRejected atomic.Bool
	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(driftedRB).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if rb, ok := obj.(*rbacv1.RoleBinding); ok {
					if rb.Name == "test-operator-scoped-access-binding" && !updateRejected.Load() {
						updateRejected.Store(true)
						return apierrors.NewInvalid(
							rbacv1.SchemeGroupVersion.WithKind("RoleBinding").GroupKind(),
							rb.Name,
							nil,
						)
					}
				}
				return cl.Update(ctx, obj, opts...)
			},
		})

	scoper := newTestScoper(t, s, builder)
	cr := newTestCR()
	ctx := context.Background()

	// EnsureAccess should succeed by detecting the invalid error and recreating.
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess should recover from RoleBinding drift, got error: %v", err)
	}

	// Verify the RoleBinding now has the correct RoleRef.
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist after drift recovery: %v", err)
	}

	if rb.RoleRef.Name != "test-operator-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-scoped-access, got %q", rb.RoleRef.Name)
	}
	if rb.Subjects[0].Name != "test-operator-sa" {
		t.Errorf("expected Subject Name = test-operator-sa, got %q", rb.Subjects[0].Name)
	}

	// Verify the interceptor was triggered (the drift path was actually exercised).
	if !updateRejected.Load() {
		t.Error("expected the interceptor to reject at least one Update, but it was never triggered")
	}
}

// --- Phase 2: Cross-Namespace Tests ---

func TestEnsureAccessInNamespace_CreatesInTargetNS(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Owner lives in "owner-ns", target is "remote-ns"
	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-cr",
			Namespace: "owner-ns",
			UID:       types.UID("cross-uid-1"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace returned error: %v", err)
	}

	// Verify Role was created in remote-ns (not owner-ns)
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "remote-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist in remote-ns, got error: %v", err)
	}

	// Verify Role has annotation-based ownership (not OwnerReferences)
	if len(role.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences on cross-namespace Role, got %d", len(role.OwnerReferences))
	}

	annotations := role.GetAnnotations()
	ownerAnnotation := annotations[ownerAnnotationKey]
	expectedKey := "owner-ns/cross-cr/cross-uid-1"
	if ownerAnnotation != expectedKey {
		t.Errorf("expected owner annotation %q, got %q", expectedKey, ownerAnnotation)
	}

	// Verify Role rules match the scoper's configured rules
	if len(role.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(role.Rules))
	}
	if role.Rules[0].Resources[0] != "secrets" {
		t.Errorf("expected rule for secrets, got %v", role.Rules[0].Resources)
	}

	// Verify Role labels
	if role.Labels["app.kubernetes.io/managed-by"] != "test-operator" {
		t.Errorf("expected managed-by label = test-operator, got %q", role.Labels["app.kubernetes.io/managed-by"])
	}
	if role.Labels["app.kubernetes.io/component"] != "rbac-scoper" {
		t.Errorf("expected component label = rbac-scoper, got %q", role.Labels["app.kubernetes.io/component"])
	}

	// Verify RoleBinding was created in remote-ns
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "remote-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist in remote-ns, got error: %v", err)
	}

	// Verify RoleBinding has annotation-based ownership
	if len(rb.OwnerReferences) != 0 {
		t.Errorf("expected no OwnerReferences on cross-namespace RoleBinding, got %d", len(rb.OwnerReferences))
	}
	rbAnnotation := rb.GetAnnotations()[ownerAnnotationKey]
	if rbAnnotation != expectedKey {
		t.Errorf("expected RoleBinding owner annotation %q, got %q", expectedKey, rbAnnotation)
	}

	// Verify RoleBinding RoleRef
	if rb.RoleRef.Name != "test-operator-scoped-access" {
		t.Errorf("expected RoleRef Name = test-operator-scoped-access, got %q", rb.RoleRef.Name)
	}
	if rb.RoleRef.APIGroup != "rbac.authorization.k8s.io" {
		t.Errorf("expected RoleRef APIGroup = rbac.authorization.k8s.io, got %q", rb.RoleRef.APIGroup)
	}

	// Verify RoleBinding Subjects
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 Subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "test-operator-sa" {
		t.Errorf("expected Subject Name = test-operator-sa, got %q", rb.Subjects[0].Name)
	}
	if rb.Subjects[0].Namespace != "operator-system" {
		t.Errorf("expected Subject Namespace = operator-system, got %q", rb.Subjects[0].Namespace)
	}
}

func TestEnsureAccessInNamespace_DelegatesForSameNamespace(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-ns-cr",
			Namespace: "my-ns",
			UID:       types.UID("same-ns-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// targetNS == owner's namespace should delegate to EnsureAccess
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "my-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace returned error: %v", err)
	}

	// Verify Role exists in the same namespace
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "my-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist in my-ns, got error: %v", err)
	}

	// Since it delegates to EnsureAccess, it should use OwnerReferences (NOT annotations)
	if len(role.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference (delegated to EnsureAccess), got %d", len(role.OwnerReferences))
	}
	if role.OwnerReferences[0].Name != "same-ns-cr" {
		t.Errorf("expected OwnerReference Name = same-ns-cr, got %q", role.OwnerReferences[0].Name)
	}

	// Should NOT have annotation-based ownership
	annotations := role.GetAnnotations()
	if annotations != nil {
		if _, hasAnnotation := annotations[ownerAnnotationKey]; hasAnnotation {
			t.Error("expected no owner annotation when delegating to same-namespace EnsureAccess")
		}
	}

	// Verify RoleBinding uses OwnerReferences too
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "my-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist in my-ns, got error: %v", err)
	}
	if len(rb.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference on RoleBinding (delegated), got %d", len(rb.OwnerReferences))
	}
}

func TestEnsureAccessInNamespace_DeniedNamespace(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "denied-cr",
			Namespace: "app-ns",
			UID:       types.UID("denied-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// Test exact match: kube-system is in the default denied list
	err := scoper.EnsureAccessInNamespace(ctx, cr, "kube-system")
	if err == nil {
		t.Fatal("expected error for denied namespace kube-system, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected error about denied namespace, got %q", err.Error())
	}

	// Test prefix match: openshift- matches any namespace starting with "openshift-"
	err = scoper.EnsureAccessInNamespace(ctx, cr, "openshift-monitoring")
	if err == nil {
		t.Fatal("expected error for denied namespace openshift-monitoring, got nil")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected error about denied namespace, got %q", err.Error())
	}

	// Test another prefix match
	err = scoper.EnsureAccessInNamespace(ctx, cr, "openshift-ingress")
	if err == nil {
		t.Fatal("expected error for denied namespace openshift-ingress, got nil")
	}

	// Test exact match: default
	err = scoper.EnsureAccessInNamespace(ctx, cr, "default")
	if err == nil {
		t.Fatal("expected error for denied namespace default, got nil")
	}

	// Test non-denied namespace should succeed
	err = scoper.EnsureAccessInNamespace(ctx, cr, "my-app-ns")
	if err != nil {
		t.Fatalf("expected non-denied namespace to succeed, got error: %v", err)
	}
}

func TestEnsureAccessInNamespace_Idempotent(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "idem-cr",
			Namespace: "owner-ns",
			UID:       types.UID("idem-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// First call
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns"); err != nil {
		t.Fatalf("first EnsureAccessInNamespace returned error: %v", err)
	}

	// Second call should not error and should not duplicate annotations
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns"); err != nil {
		t.Fatalf("second EnsureAccessInNamespace returned error: %v", err)
	}

	// Verify Role still exists with exactly one annotation entry
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "remote-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}

	ownerAnnotation := role.GetAnnotations()[ownerAnnotationKey]
	expectedKey := "owner-ns/idem-cr/idem-uid"
	if ownerAnnotation != expectedKey {
		t.Errorf("expected single owner annotation %q, got %q (possible duplication)", expectedKey, ownerAnnotation)
	}

	// Verify RoleBinding also has exactly one annotation entry
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "remote-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}

	rbAnnotation := rb.GetAnnotations()[ownerAnnotationKey]
	if rbAnnotation != expectedKey {
		t.Errorf("expected single owner annotation on RoleBinding %q, got %q", expectedKey, rbAnnotation)
	}
}

func TestCleanupAllAccess_CleansAcrossNamespaces(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-ns-cr",
			Namespace: "owner-ns",
			UID:       types.UID("multi-ns-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// Create access in same namespace (uses OwnerReferences)
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "owner-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace (same-ns) failed: %v", err)
	}

	// Create access in remote namespace (uses annotations)
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns-1"); err != nil {
		t.Fatalf("EnsureAccessInNamespace (remote-ns-1) failed: %v", err)
	}
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns-2"); err != nil {
		t.Fatalf("EnsureAccessInNamespace (remote-ns-2) failed: %v", err)
	}

	// Cleanup all access
	if err := scoper.CleanupAllAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAllAccess returned error: %v", err)
	}

	// Verify all Roles and RoleBindings are gone
	for _, ns := range []string{"owner-ns", "remote-ns-1", "remote-ns-2"} {
		role := &rbacv1.Role{}
		err := scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access", Namespace: ns,
		}, role)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected Role in %s to be deleted, got err=%v", ns, err)
		}

		rb := &rbacv1.RoleBinding{}
		err = scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access-binding", Namespace: ns,
		}, rb)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected RoleBinding in %s to be deleted, got err=%v", ns, err)
		}
	}
}

func TestCleanupAllAccess_MultiOwnerAnnotation(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Two owners from different namespaces, both granting access to the same remote-ns
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

	// Both grant access to the same remote namespace
	if err := scoper.EnsureAccessInNamespace(ctx, cr1, "shared-remote"); err != nil {
		t.Fatalf("EnsureAccessInNamespace for cr1 failed: %v", err)
	}
	if err := scoper.EnsureAccessInNamespace(ctx, cr2, "shared-remote"); err != nil {
		t.Fatalf("EnsureAccessInNamespace for cr2 failed: %v", err)
	}

	// Verify both owners are in the annotation
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	annotation := role.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(annotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected annotation to contain cr1's key, got %q", annotation)
	}
	if !strings.Contains(annotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected annotation to contain cr2's key, got %q", annotation)
	}

	// Cleanup only cr1
	if err := scoper.CleanupAllAccess(ctx, cr1); err != nil {
		t.Fatalf("CleanupAllAccess for cr1 failed: %v", err)
	}

	// Role should still exist with cr2's annotation
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role); err != nil {
		t.Fatal("Role was deleted when another owner (cr2) still exists")
	}
	remainingAnnotation := role.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(remainingAnnotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected remaining annotation to contain cr2's key, got %q", remainingAnnotation)
	}
	if strings.Contains(remainingAnnotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected cr1's key to be removed from annotation, got %q", remainingAnnotation)
	}

	// RoleBinding should also still exist
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "shared-remote",
	}, rb); err != nil {
		t.Fatal("RoleBinding was deleted when another owner (cr2) still exists")
	}

	// Cleanup cr2 -- now everything should be deleted
	if err := scoper.CleanupAllAccess(ctx, cr2); err != nil {
		t.Fatalf("CleanupAllAccess for cr2 failed: %v", err)
	}

	err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to be deleted after all owners cleaned up, got err=%v", err)
	}

	err = scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "shared-remote",
	}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted after all owners cleaned up, got err=%v", err)
	}
}

func TestCleanupAllAccess_NoResourcesExist(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nonexistent-cr",
			Namespace: "some-ns",
			UID:       types.UID("nonexistent-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// CleanupAllAccess when no managed resources exist should not error
	if err := scoper.CleanupAllAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAllAccess returned error when no resources exist: %v", err)
	}
}

func TestIsDeniedNamespace(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	allowed, _ := NewAllowedRules(rbacv1.PolicyRule{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
	})

	// Default denied list includes: kube-system, kube-public, kube-node-lease, default, openshift-
	scoper, err := NewRBACScoper(cl, s,
		OperatorIdentity{Name: "op", ServiceAccount: "sa", Namespace: "ns"},
		allowed,
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		ns       string
		expected bool
	}{
		// Exact matches
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"default", true},
		// Prefix matches (openshift-)
		{"openshift-monitoring", true},
		{"openshift-ingress", true},
		{"openshift-operators", true},
		{"openshift-", true}, // the prefix itself also matches
		// Non-denied namespaces
		{"my-app", false},
		{"production", false},
		{"kube", false},           // "kube" alone is not denied (not exact match for kube-system)
		{"defaulting", false},     // "defaulting" is not "default"
		{"openshift", false},      // "openshift" without trailing "-" doesn't match "openshift-"
		{"not-openshift-ns", false},
	}

	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			result := scoper.isDeniedNamespace(tt.ns)
			if result != tt.expected {
				t.Errorf("isDeniedNamespace(%q) = %v, want %v", tt.ns, result, tt.expected)
			}
		})
	}

	// Test with custom denied namespaces
	scoper2, err := NewRBACScoper(cl, s,
		OperatorIdentity{Name: "op", ServiceAccount: "sa", Namespace: "ns"},
		allowed,
		WithDeniedNamespaces("custom-ns", "prefix-"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !scoper2.isDeniedNamespace("custom-ns") {
		t.Error("expected custom-ns to be denied")
	}
	if !scoper2.isDeniedNamespace("prefix-something") {
		t.Error("expected prefix-something to be denied via prefix match")
	}
	if scoper2.isDeniedNamespace("kube-system") {
		t.Error("kube-system should NOT be denied when custom list replaces defaults")
	}
}

func TestEnsureAccessInNamespace_RejectsClusterScopedOwner(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Create a cluster-scoped resource (no namespace)
	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
			// No Namespace -- cluster-scoped
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	// EnsureAccessInNamespace should reject cluster-scoped owners
	err := scoper.EnsureAccessInNamespace(ctx, clusterCR, "some-target-ns")
	if err == nil {
		t.Fatal("expected error for cluster-scoped owner in EnsureAccessInNamespace, got nil")
	}
	if !strings.Contains(err.Error(), "namespace-scoped") {
		t.Errorf("expected error about namespace-scoped, got %q", err.Error())
	}

	// CleanupAllAccess should also reject cluster-scoped owners
	err = scoper.CleanupAllAccess(ctx, clusterCR)
	if err == nil {
		t.Fatal("expected error from CleanupAllAccess for cluster-scoped owner, got nil")
	}
	if !strings.Contains(err.Error(), "namespace-scoped") {
		t.Errorf("CleanupAllAccess: expected error about namespace-scoped, got %q", err.Error())
	}
}

func TestAddOwner_MaxAnnotationOwnersLimit(t *testing.T) {
	tracker := &annotationOwnerTracker{annotationKey: ownerAnnotationKey}

	obj := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "limit-test",
			Namespace: "test-ns",
		},
	}

	// Add maxAnnotationOwners owners (should all succeed)
	for i := 0; i < maxAnnotationOwners; i++ {
		owner := &testResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("owner-%d", i),
				Namespace: "owner-ns",
				UID:       types.UID(fmt.Sprintf("uid-%d", i)),
			},
		}
		if err := tracker.addOwner(obj, owner); err != nil {
			t.Fatalf("addOwner failed at i=%d: %v", i, err)
		}
	}

	// The 101st addition should return an error
	extraOwner := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owner-overflow",
			Namespace: "owner-ns",
			UID:       types.UID("uid-overflow"),
		},
	}
	err := tracker.addOwner(obj, extraOwner)
	if err == nil {
		t.Fatal("expected error when exceeding maxAnnotationOwners, got nil")
	}
	if !strings.Contains(err.Error(), "maximum owner count") {
		t.Errorf("expected error about maximum owner count, got %q", err.Error())
	}
}

func TestEnsureAccessInNamespace_EmptyTargetNS(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-target-cr",
			Namespace: "owner-ns",
			UID:       types.UID("empty-target-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	err := scoper.EnsureAccessInNamespace(ctx, cr, "")
	if err == nil {
		t.Fatal("expected error for empty targetNS, got nil")
	}
	if !strings.Contains(err.Error(), "targetNS must not be empty") {
		t.Errorf("expected error containing 'targetNS must not be empty', got %q", err.Error())
	}
}

func TestEnsureAccess_AllowAllRulesProducesEmptyRole(t *testing.T) {
	s := testScheme()
	cl := fake.NewClientBuilder().WithScheme(s).Build()

	scoper, err := NewRBACScoper(
		cl,
		s,
		OperatorIdentity{
			Name:           "test-operator",
			ServiceAccount: "test-operator-sa",
			Namespace:      "operator-system",
		},
		AllowAllRules(),
	)
	if err != nil {
		t.Fatalf("NewRBACScoper failed: %v", err)
	}

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allowall-cr",
			Namespace: "target-ns",
			UID:       types.UID("allowall-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify the Role was created with zero rules (documents current behavior)
	role := &rbacv1.Role{}
	if err := cl.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist, got error: %v", err)
	}

	if len(role.Rules) != 0 {
		t.Errorf("expected 0 rules with AllowAllRules (documents current behavior), got %d", len(role.Rules))
	}
}

func TestCleanupAllAccess_Pagination(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "paginated-cr",
			Namespace: "owner-ns",
			UID:       types.UID("paginated-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// Create access in the owner's namespace (uses OwnerReferences)
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "owner-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace (owner-ns) failed: %v", err)
	}

	// Create access in multiple remote namespaces (uses annotations)
	remoteNamespaces := []string{"remote-ns-a", "remote-ns-b", "remote-ns-c"}
	for _, ns := range remoteNamespaces {
		if err := scoper.EnsureAccessInNamespace(ctx, cr, ns); err != nil {
			t.Fatalf("EnsureAccessInNamespace (%s) failed: %v", ns, err)
		}
	}

	allNamespaces := append([]string{"owner-ns"}, remoteNamespaces...)

	// Verify all Roles and RoleBindings exist before cleanup
	for _, ns := range allNamespaces {
		role := &rbacv1.Role{}
		if err := scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access", Namespace: ns,
		}, role); err != nil {
			t.Fatalf("expected Role to exist in %s before cleanup: %v", ns, err)
		}
		rb := &rbacv1.RoleBinding{}
		if err := scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access-binding", Namespace: ns,
		}, rb); err != nil {
			t.Fatalf("expected RoleBinding to exist in %s before cleanup: %v", ns, err)
		}
	}

	// CleanupAllAccess should clean up all resources across all namespaces,
	// exercising the paginated listing code path (the fake client returns
	// all results in one page, but the pagination loop still executes).
	if err := scoper.CleanupAllAccess(ctx, cr); err != nil {
		t.Fatalf("CleanupAllAccess returned error: %v", err)
	}

	// Verify all Roles and RoleBindings are deleted
	for _, ns := range allNamespaces {
		role := &rbacv1.Role{}
		err := scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access", Namespace: ns,
		}, role)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected Role in %s to be deleted, got err=%v", ns, err)
		}

		rb := &rbacv1.RoleBinding{}
		err = scoper.client.Get(ctx, types.NamespacedName{
			Name: "test-operator-scoped-access-binding", Namespace: ns,
		}, rb)
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected RoleBinding in %s to be deleted, got err=%v", ns, err)
		}
	}
}

func TestAnnotationCorruptionResilience(t *testing.T) {
	tracker := &annotationOwnerTracker{annotationKey: ownerAnnotationKey}

	// Helper to create an object with a pre-set annotation value.
	objWithAnnotation := func(value string) *testResource {
		return &testResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "corrupted-obj",
				Namespace: "test-ns",
				Annotations: map[string]string{
					ownerAnnotationKey: value,
				},
			},
		}
	}

	// Helper to create an owner object for use in addOwner/removeOwner.
	makeOwner := func(ns, name, uid string) *testResource {
		return &testResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ns,
				UID:       types.UID(uid),
			},
		}
	}

	t.Run("trailing commas", func(t *testing.T) {
		obj := objWithAnnotation("ns/name/uid,")

		if !tracker.hasOwners(obj) {
			t.Error("hasOwners should return true when a valid entry exists before trailing comma")
		}

		// removeOwner with a different owner should preserve the valid entry
		differentOwner := makeOwner("other-ns", "other-name", "other-uid")
		tracker.removeOwner(obj, differentOwner)

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		if annotation != "ns/name/uid" {
			t.Errorf("expected annotation to be %q after removing non-existent owner, got %q", "ns/name/uid", annotation)
		}
	})

	t.Run("leading commas", func(t *testing.T) {
		obj := objWithAnnotation(",ns/name/uid")

		if !tracker.hasOwners(obj) {
			t.Error("hasOwners should return true when a valid entry exists after leading comma")
		}

		// removeOwner with a different owner should preserve the valid entry
		differentOwner := makeOwner("other-ns", "other-name", "other-uid")
		tracker.removeOwner(obj, differentOwner)

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		if annotation != "ns/name/uid" {
			t.Errorf("expected annotation to be %q after removing non-existent owner, got %q", "ns/name/uid", annotation)
		}
	})

	t.Run("multiple commas", func(t *testing.T) {
		obj := objWithAnnotation("ns/name/uid,,,ns2/name2/uid2")

		if !tracker.hasOwners(obj) {
			t.Error("hasOwners should return true when valid entries exist between multiple commas")
		}

		// removeOwner with a non-matching owner should preserve both valid entries
		differentOwner := makeOwner("other-ns", "other-name", "other-uid")
		tracker.removeOwner(obj, differentOwner)

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		if !strings.Contains(annotation, "ns/name/uid") {
			t.Errorf("expected annotation to contain %q, got %q", "ns/name/uid", annotation)
		}
		if !strings.Contains(annotation, "ns2/name2/uid2") {
			t.Errorf("expected annotation to contain %q, got %q", "ns2/name2/uid2", annotation)
		}
	})

	t.Run("only commas", func(t *testing.T) {
		obj := objWithAnnotation(",,,")

		if tracker.hasOwners(obj) {
			t.Error("hasOwners should return false when annotation contains only commas")
		}
	})

	t.Run("whitespace entries", func(t *testing.T) {
		obj := objWithAnnotation("  ,  ,  ")

		if tracker.hasOwners(obj) {
			t.Error("hasOwners should return false when annotation contains only whitespace entries")
		}
	})

	t.Run("entry without UID", func(t *testing.T) {
		obj := objWithAnnotation("ns/name")

		// "ns/name" is a non-empty string entry, even if malformed
		if !tracker.hasOwners(obj) {
			t.Error("hasOwners should return true for non-empty malformed entry")
		}

		// removeOwner with "ns/name/uid" should NOT remove "ns/name" (different key)
		owner := makeOwner("ns", "name", "uid")
		tracker.removeOwner(obj, owner)

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		if annotation != "ns/name" {
			t.Errorf("expected malformed entry %q to be preserved (key mismatch), got %q", "ns/name", annotation)
		}
	})

	t.Run("addOwner to corrupted annotation", func(t *testing.T) {
		obj := objWithAnnotation("corrupted,,,data")

		newOwner := makeOwner("new-ns", "new-name", "new-uid")
		if err := tracker.addOwner(obj, newOwner); err != nil {
			t.Fatalf("addOwner should succeed on corrupted annotation, got error: %v", err)
		}

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		// The new owner should be appended to the existing (corrupted) value
		if !strings.Contains(annotation, "corrupted") {
			t.Errorf("expected corrupted entries to be preserved, got %q", annotation)
		}
		if !strings.Contains(annotation, "data") {
			t.Errorf("expected corrupted entries to be preserved, got %q", annotation)
		}
		if !strings.Contains(annotation, "new-ns/new-name/new-uid") {
			t.Errorf("expected new owner to be present, got %q", annotation)
		}
	})

	t.Run("addOwner limit not inflated by empty entries", func(t *testing.T) {
		// Annotation with many consecutive commas — raw Split produces far
		// more entries than real owners. The limit check must count only
		// non-empty trimmed entries.
		corrupted := "ns1/name1/uid1" + strings.Repeat(",", 200)
		obj := objWithAnnotation(corrupted)

		newOwner := makeOwner("ns2", "name2", "uid2")
		if err := tracker.addOwner(obj, newOwner); err != nil {
			t.Fatalf("addOwner should succeed (only 1 real owner), got error: %v", err)
		}

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		if !strings.Contains(annotation, "ns2/name2/uid2") {
			t.Errorf("expected new owner in annotation, got %q", annotation)
		}
	})

	t.Run("removeOwner from corrupted annotation preserves others", func(t *testing.T) {
		// Mix of valid and corrupted entries
		obj := objWithAnnotation("corrupted-entry,ns/valid-owner/valid-uid,,,also-corrupted")

		// Remove the valid owner
		validOwner := makeOwner("ns", "valid-owner", "valid-uid")
		tracker.removeOwner(obj, validOwner)

		annotation := obj.GetAnnotations()[ownerAnnotationKey]
		// Corrupted entries should remain (they don't match the owner key)
		if !strings.Contains(annotation, "corrupted-entry") {
			t.Errorf("expected corrupted entry to be preserved, got %q", annotation)
		}
		if !strings.Contains(annotation, "also-corrupted") {
			t.Errorf("expected corrupted entry to be preserved, got %q", annotation)
		}
		// The valid owner should be removed
		if strings.Contains(annotation, "ns/valid-owner/valid-uid") {
			t.Errorf("expected valid owner to be removed, got %q", annotation)
		}
	})
}

// --- CleanupAccessInNamespace Tests ---

func TestCleanupAccessInNamespace_SameNamespaceDelegation(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "same-ns-cr",
			Namespace: "my-ns",
			UID:       types.UID("same-ns-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// Create access in same namespace (uses OwnerReferences via EnsureAccess delegation)
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "my-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace returned error: %v", err)
	}

	// Verify resources exist
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "my-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	if len(role.OwnerReferences) != 1 {
		t.Fatalf("expected 1 OwnerReference, got %d", len(role.OwnerReferences))
	}

	// CleanupAccessInNamespace with same namespace should delegate to CleanupAccess
	if err := scoper.CleanupAccessInNamespace(ctx, cr, "my-ns"); err != nil {
		t.Fatalf("CleanupAccessInNamespace returned error: %v", err)
	}

	// Verify Role is deleted (single owner, so OwnerRef removal leads to deletion)
	err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "my-ns",
	}, role)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to be deleted after same-namespace cleanup, got err=%v", err)
	}

	// Verify RoleBinding is also deleted
	rb := &rbacv1.RoleBinding{}
	err = scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "my-ns",
	}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted after same-namespace cleanup, got err=%v", err)
	}
}

func TestCleanupAccessInNamespace_CrossNamespaceCleanup(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-cr",
			Namespace: "owner-ns",
			UID:       types.UID("cross-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// Create cross-namespace access
	if err := scoper.EnsureAccessInNamespace(ctx, cr, "remote-ns"); err != nil {
		t.Fatalf("EnsureAccessInNamespace returned error: %v", err)
	}

	// Verify resources exist in remote-ns
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "remote-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist in remote-ns: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "remote-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist in remote-ns: %v", err)
	}

	// Cleanup cross-namespace access
	if err := scoper.CleanupAccessInNamespace(ctx, cr, "remote-ns"); err != nil {
		t.Fatalf("CleanupAccessInNamespace returned error: %v", err)
	}

	// Verify Role is deleted
	err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "remote-ns",
	}, role)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to be deleted after cross-namespace cleanup, got err=%v", err)
	}

	// Verify RoleBinding is deleted
	err = scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "remote-ns",
	}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted after cross-namespace cleanup, got err=%v", err)
	}
}

func TestCleanupAccessInNamespace_PreservesOtherOwners(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Two owners from different namespaces, both granting access to the same remote-ns
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

	// Both grant access to the same remote namespace
	if err := scoper.EnsureAccessInNamespace(ctx, cr1, "shared-remote"); err != nil {
		t.Fatalf("EnsureAccessInNamespace for cr1 failed: %v", err)
	}
	if err := scoper.EnsureAccessInNamespace(ctx, cr2, "shared-remote"); err != nil {
		t.Fatalf("EnsureAccessInNamespace for cr2 failed: %v", err)
	}

	// Verify both owners are in the annotation
	role := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role); err != nil {
		t.Fatalf("expected Role to exist: %v", err)
	}
	annotation := role.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(annotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected annotation to contain cr1's key, got %q", annotation)
	}
	if !strings.Contains(annotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected annotation to contain cr2's key, got %q", annotation)
	}

	// Cleanup only cr1 using CleanupAccessInNamespace
	if err := scoper.CleanupAccessInNamespace(ctx, cr1, "shared-remote"); err != nil {
		t.Fatalf("CleanupAccessInNamespace for cr1 failed: %v", err)
	}

	// Role should still exist with cr2's annotation
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role); err != nil {
		t.Fatal("Role was deleted when another owner (cr2) still exists")
	}
	remainingAnnotation := role.GetAnnotations()[ownerAnnotationKey]
	if !strings.Contains(remainingAnnotation, "ns-beta/cr-beta/uid-beta") {
		t.Errorf("expected remaining annotation to contain cr2's key, got %q", remainingAnnotation)
	}
	if strings.Contains(remainingAnnotation, "ns-alpha/cr-alpha/uid-alpha") {
		t.Errorf("expected cr1's key to be removed from annotation, got %q", remainingAnnotation)
	}

	// RoleBinding should also still exist
	rb := &rbacv1.RoleBinding{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "shared-remote",
	}, rb); err != nil {
		t.Fatal("RoleBinding was deleted when another owner (cr2) still exists")
	}

	// Cleanup cr2 -- now everything should be deleted
	if err := scoper.CleanupAccessInNamespace(ctx, cr2, "shared-remote"); err != nil {
		t.Fatalf("CleanupAccessInNamespace for cr2 failed: %v", err)
	}

	err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-remote",
	}, role)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to be deleted after all owners cleaned up, got err=%v", err)
	}

	err = scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "shared-remote",
	}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted after all owners cleaned up, got err=%v", err)
	}
}

func TestCleanupAccessInNamespace_NotFoundNoError(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nonexistent-cr",
			Namespace: "some-ns",
			UID:       types.UID("nonexistent-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	// CleanupAccessInNamespace when no managed resources exist should not error
	if err := scoper.CleanupAccessInNamespace(ctx, cr, "nonexistent-remote-ns"); err != nil {
		t.Fatalf("CleanupAccessInNamespace returned error when no resources exist: %v", err)
	}
}

func TestCleanupAccessInNamespace_EmptyTargetNS(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	cr := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-target-cr",
			Namespace: "owner-ns",
			UID:       types.UID("empty-target-uid"),
		},
	}
	cr.SetGroupVersionKind(testGVK)

	err := scoper.CleanupAccessInNamespace(ctx, cr, "")
	if err == nil {
		t.Fatal("expected error for empty targetNS, got nil")
	}
	if !strings.Contains(err.Error(), "targetNS must not be empty") {
		t.Errorf("expected error containing 'targetNS must not be empty', got %q", err.Error())
	}
}

func TestCleanupAccessInNamespace_RejectsClusterScopedOwner(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)
	ctx := context.Background()

	// Create a cluster-scoped resource (no namespace)
	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
			// No Namespace -- cluster-scoped
		},
	}
	clusterCR.SetGroupVersionKind(testGVK)

	err := scoper.CleanupAccessInNamespace(ctx, clusterCR, "some-target-ns")
	if err == nil {
		t.Fatal("expected error for cluster-scoped owner in CleanupAccessInNamespace, got nil")
	}
	if !strings.Contains(err.Error(), "namespace-scoped") {
		t.Errorf("expected error about namespace-scoped, got %q", err.Error())
	}
}

// --- GarbageCollectOrphanedOwners Tests ---

// newTestResolver creates an OwnerResolver that reports entries in validEntries
// as existing and all others as orphaned.
func newTestResolver(validEntries map[string]bool) OwnerResolver {
	return func(ctx context.Context, ns, name string, uid types.UID) (bool, error) {
		key := fmt.Sprintf("%s/%s/%s", ns, name, string(uid))
		return validEntries[key], nil
	}
}

func TestGarbageCollectOrphanedOwners_RemovesStaleEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Pre-create a Role with an annotation pointing to a non-existent CR
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "remote-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
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
			Namespace: "remote-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "gone-ns/gone-cr/gone-uid",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-operator-scoped-access",
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role, rb)
	scoper := newTestScoper(t, s, builder)

	// Resolver says the owner does not exist
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
		t.Errorf("expected 2 resources deleted (no owners remain), got %d", result.ResourcesDeleted)
	}

	// Verify Role is deleted
	gotRole := &rbacv1.Role{}
	roleErr := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "remote-ns",
	}, gotRole)
	if !apierrors.IsNotFound(roleErr) {
		t.Errorf("expected Role to be deleted, got err=%v", roleErr)
	}

	// Verify RoleBinding is deleted
	gotRB := &rbacv1.RoleBinding{}
	rbErr := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access-binding", Namespace: "remote-ns",
	}, gotRB)
	if !apierrors.IsNotFound(rbErr) {
		t.Errorf("expected RoleBinding to be deleted, got err=%v", rbErr)
	}
}

func TestGarbageCollectOrphanedOwners_PreservesValidEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "remote-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "valid-ns/valid-cr/valid-uid",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	// Resolver says the owner exists
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

	// Verify Role still exists with the annotation intact
	gotRole := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "remote-ns",
	}, gotRole); err != nil {
		t.Fatalf("expected Role to still exist: %v", err)
	}
	annotation := gotRole.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation preserved as %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
}

func TestGarbageCollectOrphanedOwners_MixedEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "remote-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "valid-ns/valid-cr/valid-uid,stale-ns/stale-cr/stale-uid",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	// Only the first entry is valid
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
		t.Errorf("expected 0 resources deleted (valid owner remains), got %d", result.ResourcesDeleted)
	}

	// Verify Role still exists with only the valid annotation
	gotRole := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "remote-ns",
	}, gotRole); err != nil {
		t.Fatalf("expected Role to still exist: %v", err)
	}
	annotation := gotRole.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation to be %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
	if strings.Contains(annotation, "stale") {
		t.Errorf("expected stale entry to be removed, got %q", annotation)
	}
}

func TestGarbageCollectOrphanedOwners_DeletesResourceWithNoOwners(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Role with only stale annotation entries AND no OwnerReferences
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "orphan-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "stale-ns/stale-cr/stale-uid",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	resolver := newTestResolver(map[string]bool{}) // nothing is valid

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

	// Verify Role is deleted
	gotRole := &rbacv1.Role{}
	err = scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "orphan-ns",
	}, gotRole)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected Role to be deleted, got err=%v", err)
	}
}

func TestGarbageCollectOrphanedOwners_KeepsResourceWithOwnerRefs(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Role with stale annotation entries BUT still has an OwnerReference
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "ownerref-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "stale-ns/stale-cr/stale-uid",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "test.example.com/v1alpha1",
					Kind:       "TestResource",
					Name:       "local-cr",
					UID:        types.UID("local-uid"),
				},
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	resolver := newTestResolver(map[string]bool{}) // annotation owner is stale

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

	// Verify Role still exists but annotation is cleaned
	gotRole := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "ownerref-ns",
	}, gotRole); err != nil {
		t.Fatalf("expected Role to still exist: %v", err)
	}
	annotations := gotRole.GetAnnotations()
	if _, has := annotations[ownerAnnotationKey]; has {
		t.Errorf("expected owner annotation to be removed, got %q", annotations[ownerAnnotationKey])
	}
	if len(gotRole.OwnerReferences) != 1 {
		t.Errorf("expected OwnerReference to be preserved, got %d refs", len(gotRole.OwnerReferences))
	}
}

func TestGarbageCollectOrphanedOwners_RemovesMalformedEntries(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Role with malformed annotation entries (missing UID, bad format)
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "malformed-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "bad,ns/name,valid-ns/valid-cr/valid-uid",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

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
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted (valid owner remains), got %d", result.ResourcesDeleted)
	}

	// Verify Role still exists with only the valid annotation
	gotRole := &rbacv1.Role{}
	if err := scoper.client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "malformed-ns",
	}, gotRole); err != nil {
		t.Fatalf("expected Role to still exist: %v", err)
	}
	annotation := gotRole.GetAnnotations()[ownerAnnotationKey]
	if annotation != "valid-ns/valid-cr/valid-uid" {
		t.Errorf("expected annotation to be %q, got %q", "valid-ns/valid-cr/valid-uid", annotation)
	}
}

func TestGarbageCollectOrphanedOwners_NoOpWhenClean(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Role with a valid annotation entry
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "clean-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
			Annotations: map[string]string{
				ownerAnnotationKey: "valid-ns/valid-cr/valid-uid",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	resolver := newTestResolver(map[string]bool{
		"valid-ns/valid-cr/valid-uid": true,
	})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Errorf("expected 1 resource scanned, got %d", result.ResourcesScanned)
	}
	if result.EntriesRemoved != 0 {
		t.Errorf("expected 0 entries removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted, got %d", result.ResourcesDeleted)
	}
}

func TestGarbageCollectOrphanedOwners_NoManagedResources(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(t, s, builder)

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

func TestGarbageCollectOrphanedOwners_NoAnnotations(t *testing.T) {
	s := testScheme()
	ctx := context.Background()

	// Role with labels but no annotations
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-operator-scoped-access",
			Namespace: "no-annotation-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "test-operator",
				"app.kubernetes.io/component":  "rbac-scoper",
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(role)
	scoper := newTestScoper(t, s, builder)

	resolver := newTestResolver(map[string]bool{})

	result, err := scoper.GarbageCollectOrphanedOwners(ctx, resolver)
	if err != nil {
		t.Fatalf("GarbageCollectOrphanedOwners returned error: %v", err)
	}

	if result.ResourcesScanned != 1 {
		t.Errorf("expected 1 resource scanned, got %d", result.ResourcesScanned)
	}
	if result.EntriesRemoved != 0 {
		t.Errorf("expected 0 entries removed, got %d", result.EntriesRemoved)
	}
	if result.ResourcesDeleted != 0 {
		t.Errorf("expected 0 resources deleted, got %d", result.ResourcesDeleted)
	}
}

func TestAccessScoperInterface(t *testing.T) {
	// Verify both types satisfy the interface at runtime.
	// (Compile-time checks are in identity.go, this is for documentation.)
	var _ AccessScoper = (*RBACScoper)(nil)
	var _ AccessScoper = (*ClusterRBACScoper)(nil)
}
