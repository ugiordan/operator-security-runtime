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

func init() {
	s := testScheme()
	_ = s // ensure scheme is initialized
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

func newTestScoper(s *runtime.Scheme, cl *fake.ClientBuilder) *RBACScoper {
	return &RBACScoper{
		Client:              cl.Build(),
		Scheme:              s,
		OperatorName:        "test-operator",
		OperatorSAName:      "test-operator-sa",
		OperatorSANamespace: "operator-system",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
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
	scoper := newTestScoper(s, builder)
	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify Role was created
	role := &rbacv1.Role{}
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	scoper := newTestScoper(s, builder)
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
	if err := scoper.Client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role); err != nil {
		t.Fatalf("expected Role to exist after idempotent call, got error: %v", err)
	}

	// Verify RoleBinding still exists
	rb := &rbacv1.RoleBinding{}
	if err := scoper.Client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access-binding",
		Namespace: "target-ns",
	}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist after idempotent call, got error: %v", err)
	}
}

func TestEnsureAccess_CustomRules(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := &RBACScoper{
		Client:              builder.Build(),
		Scheme:              s,
		OperatorName:        "test-operator",
		OperatorSAName:      "test-operator-sa",
		OperatorSANamespace: "operator-system",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "create", "update"},
		}},
	}
	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	role := &rbacv1.Role{}
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	scoper := newTestScoper(s, builder)
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
	err := scoper.Client.Get(ctx, types.NamespacedName{
		Name:      "test-operator-scoped-access",
		Namespace: "target-ns",
	}, role)
	if err == nil {
		t.Fatal("expected Role to be deleted, but it still exists")
	}

	// Verify RoleBinding is gone
	rb := &rbacv1.RoleBinding{}
	err = scoper.Client.Get(ctx, types.NamespacedName{
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
	scoper := newTestScoper(s, builder)
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
	scoper := newTestScoper(s, builder)
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
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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

	err := scoper.Client.Get(ctx, types.NamespacedName{
		Name: "test-operator-scoped-access", Namespace: "shared-ns",
	}, role)
	if err == nil {
		t.Fatal("expected Role to be deleted after all owners cleaned up")
	}
}

func TestEnsureAccess_MultiResourceRules(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := &RBACScoper{
		Client:              builder.Build(),
		Scheme:              s,
		OperatorName:        "test-operator",
		OperatorSAName:      "test-operator-sa",
		OperatorSANamespace: "operator-system",
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	cr := newTestCR()
	ctx := context.Background()

	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess returned error: %v", err)
	}

	// Verify Role was created with both rules
	role := &rbacv1.Role{}
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
	scoper := &RBACScoper{
		Client:              cl,
		Scheme:              s,
		OperatorName:        "test-operator",
		OperatorSAName:      "test-operator-sa",
		OperatorSANamespace: "operator-system",
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	cr := newTestCR()
	ctx := context.Background()

	// First call: secrets only
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
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

	// Reconfigure scoper to include configmaps
	scoper.Rules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"},
		},
	}

	// Second call: should update the Role with 2 rules
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
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

func TestEnsureAccess_ValidationErrors(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	cl := builder.Build()
	ctx := context.Background()
	cr := newTestCR()

	tests := []struct {
		name    string
		scoper *RBACScoper
		errMsg string
	}{
		{
			name: "nil Client",
			scoper: &RBACScoper{
				Client:              nil,
				Scheme:              s,
				OperatorName:        "test",
				OperatorSAName:      "test-sa",
				OperatorSANamespace: "test-ns",
				Rules:               []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
			},
			errMsg: "Client must not be nil",
		},
		{
			name: "nil Scheme",
			scoper: &RBACScoper{
				Client:              cl,
				Scheme:              nil,
				OperatorName:        "test",
				OperatorSAName:      "test-sa",
				OperatorSANamespace: "test-ns",
				Rules:               []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
			},
			errMsg: "Scheme must not be nil",
		},
		{
			name: "empty OperatorName",
			scoper: &RBACScoper{
				Client:              cl,
				Scheme:              s,
				OperatorName:        "",
				OperatorSAName:      "test-sa",
				OperatorSANamespace: "test-ns",
				Rules:               []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
			},
			errMsg: "OperatorName must not be empty",
		},
		{
			name: "empty OperatorSAName",
			scoper: &RBACScoper{
				Client:              cl,
				Scheme:              s,
				OperatorName:        "test",
				OperatorSAName:      "",
				OperatorSANamespace: "test-ns",
				Rules:               []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
			},
			errMsg: "OperatorSAName must not be empty",
		},
		{
			name: "empty OperatorSANamespace",
			scoper: &RBACScoper{
				Client:              cl,
				Scheme:              s,
				OperatorName:        "test",
				OperatorSAName:      "test-sa",
				OperatorSANamespace: "",
				Rules:               []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
			},
			errMsg: "OperatorSANamespace must not be empty",
		},
		{
			name: "empty Rules",
			scoper: &RBACScoper{
				Client:              cl,
				Scheme:              s,
				OperatorName:        "test",
				OperatorSAName:      "test-sa",
				OperatorSANamespace: "test-ns",
				Rules:               nil,
			},
			errMsg: "Rules must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scoper.EnsureAccess(ctx, cr)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}

			// CleanupAccess should return the same validation error
			err = tt.scoper.CleanupAccess(ctx, cr)
			if err == nil {
				t.Fatal("expected error from CleanupAccess, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("CleanupAccess: expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestEnsureAccess_RejectsClusterScopedOwner(t *testing.T) {
	s := testScheme()
	builder := fake.NewClientBuilder().WithScheme(s)
	scoper := newTestScoper(s, builder)
	ctx := context.Background()

	// Create a cluster-scoped resource (no namespace)
	clusterCR := &testResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-scoped-cr",
			UID:  types.UID("cluster-uid"),
			// No Namespace — cluster-scoped
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

	scoper := newTestScoper(s, builder)
	cr := newTestCR()
	ctx := context.Background()

	// EnsureAccess should succeed by detecting the invalid error and recreating.
	if err := scoper.EnsureAccess(ctx, cr); err != nil {
		t.Fatalf("EnsureAccess should recover from RoleBinding drift, got error: %v", err)
	}

	// Verify the RoleBinding now has the correct RoleRef.
	rb := &rbacv1.RoleBinding{}
	if err := scoper.Client.Get(ctx, types.NamespacedName{
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
