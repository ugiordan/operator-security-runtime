package saprotection

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ctxWithUser creates a context containing an AdmissionRequest with the given UserInfo.
// This simulates the context that controller-runtime provides during real webhook calls.
func ctxWithUser(username string, groups ...string) context.Context {
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: username,
				Groups:   groups,
			},
		},
	}
	return admission.NewContextWithRequest(context.Background(), req)
}

// newValidator creates a PodCustomValidator with the default protected identity.
func newValidator() *PodCustomValidator {
	return &PodCustomValidator{
		ProtectedIdentities: []ProtectedIdentity{
			{
				Namespace:          ExampleOperatorNamespace,
				ServiceAccountName: ExampleOperatorServiceAccountName,
			},
		},
	}
}

// newMultiValidator creates a PodCustomValidator protecting multiple ServiceAccounts.
func newMultiValidator() *PodCustomValidator {
	return &PodCustomValidator{
		ProtectedIdentities: []ProtectedIdentity{
			{
				Namespace:          ExampleOperatorNamespace,
				ServiceAccountName: ExampleOperatorServiceAccountName,
			},
			{
				Namespace:          "other-operator-system",
				ServiceAccountName: "other-operator-controller-manager",
			},
		},
	}
}

func TestValidateCreate(t *testing.T) {
	operatorIdentity := ProtectedIdentity{
		Namespace:          ExampleOperatorNamespace,
		ServiceAccountName: ExampleOperatorServiceAccountName,
	}.ExpectedCreator()

	tests := []struct {
		name      string
		validator *PodCustomValidator
		pod       *corev1.Pod
		ctx       context.Context
		wantAllow bool
		wantMsg   string // substring expected in error message when denied
	}{
		{
			name:      "regular user creates pod with operator SA - deny",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "malicious-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("user@redhat.com", "system:authenticated"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		{
			name:      "cluster-admin creates pod with operator SA - deny (defense-in-depth)",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "admin-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("admin@redhat.com", "system:masters", "system:authenticated"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		{
			name:      "other serviceaccount creates pod with operator SA - deny",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "other-sa-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("system:serviceaccount:other-ns:other-sa"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		{
			name:      "operator creates pod with its own SA - allow",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "operator-workload", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser(operatorIdentity),
			wantAllow: true,
		},
		{
			name:      "user creates pod with default SA - allow (not protected)",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "normal-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: "default"},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true,
		},
		{
			name:      "user creates pod with no SA specified - allow",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "no-sa-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true,
		},
		{
			name:      "user creates pod with unrelated SA - allow",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "custom-sa-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: "my-app-sa"},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true,
		},
		{
			name:      "no admission request in context - fail-secure (deny)",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "no-ctx-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       context.Background(), // no admission request
			wantAllow: false,
			wantMsg:   "unable to identify request creator",
		},
		{
			name:      "deprecated ServiceAccount field with operator SA - deny",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "legacy-pod", Namespace: "user-project"},
				Spec: corev1.PodSpec{
					DeprecatedServiceAccount: ExampleOperatorServiceAccountName, //nolint:staticcheck
				},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		{
			name:      "both SA fields set - ServiceAccountName takes precedence (allow if ServiceAccountName is safe)",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "both-fields-pod", Namespace: "user-project"},
				Spec: corev1.PodSpec{
					ServiceAccountName:       "default",
					DeprecatedServiceAccount: ExampleOperatorServiceAccountName, //nolint:staticcheck
				},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true, // ServiceAccountName takes precedence, "default" is not protected
		},
		{
			name:      "error message does not contain impersonation instructions",
			validator: newValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "check-msg-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		// Multi-identity tests
		{
			name:      "multi-identity: user creates pod with second protected SA - deny",
			validator: newMultiValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: "other-operator-controller-manager"},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		{
			name:      "multi-identity: correct operator creates pod with its SA - allow",
			validator: newMultiValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-ok-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: "other-operator-controller-manager"},
			},
			ctx:       ctxWithUser("system:serviceaccount:other-operator-system:other-operator-controller-manager"),
			wantAllow: true,
		},
		{
			name:      "multi-identity: wrong operator tries to use other operator's SA - deny",
			validator: newMultiValidator(),
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "cross-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: "other-operator-controller-manager"},
			},
			ctx:       ctxWithUser(operatorIdentity), // first operator's identity
			wantAllow: false,
			wantMsg:   "unauthorized",
		},
		// Empty validator (no protected identities configured)
		{
			name: "no protected identities configured - allow all",
			validator: &PodCustomValidator{
				ProtectedIdentities: []ProtectedIdentity{},
			},
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "any-pod", Namespace: "user-project"},
				Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := tt.validator.ValidateCreate(tt.ctx, tt.pod)

			if tt.wantAllow {
				if err != nil {
					t.Errorf("expected allow, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected deny, got allow")
				} else if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}

			_ = warnings
		})
	}
}

func TestValidateCreate_ErrorMessageDoesNotLeakBypassInstructions(t *testing.T) {
	validator := newValidator()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "leak-test", Namespace: "user-project"},
		Spec:       corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
	}
	ctx := ctxWithUser("attacker@evil.com")

	_, err := validator.ValidateCreate(ctx, pod)
	if err == nil {
		t.Fatal("expected deny, got allow")
	}

	msg := err.Error()
	// Error should NOT contain impersonation instructions (security review MEDIUM-1)
	if strings.Contains(msg, "--as=") {
		t.Errorf("error message leaks impersonation bypass instructions: %s", msg)
	}
	if strings.Contains(msg, "impersonation") {
		t.Errorf("error message mentions impersonation: %s", msg)
	}
}

func TestValidateUpdate(t *testing.T) {
	operatorIdentity := ProtectedIdentity{
		Namespace:          ExampleOperatorNamespace,
		ServiceAccountName: ExampleOperatorServiceAccountName,
	}.ExpectedCreator()

	tests := []struct {
		name      string
		oldPod    *corev1.Pod
		newPod    *corev1.Pod
		ctx       context.Context
		wantAllow bool
	}{
		{
			name: "SA unchanged (kubelet status update) - allow (short-circuit)",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("system:node:node-1", "system:nodes"),
			wantAllow: true, // short-circuits because SA is unchanged
		},
		{
			name: "SA changed by user to operator SA - deny",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: "default"},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: false,
		},
		{
			name: "SA changed by operator to its own SA - allow",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: "default"},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
			},
			ctx:       ctxWithUser(operatorIdentity),
			wantAllow: true,
		},
		{
			name: "user updates pod with default SA (unchanged) - allow",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: "default"},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{ServiceAccountName: "default"},
			},
			ctx:       ctxWithUser("user@redhat.com"),
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := newValidator()
			_, err := validator.ValidateUpdate(tt.ctx, tt.oldPod, tt.newPod)

			if tt.wantAllow && err != nil {
				t.Errorf("expected allow, got error: %v", err)
			}
			if !tt.wantAllow && err == nil {
				t.Errorf("expected deny, got allow")
			}
		})
	}
}

func TestValidateDelete(t *testing.T) {
	validator := newValidator()
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{ServiceAccountName: ExampleOperatorServiceAccountName},
	}

	_, err := validator.ValidateDelete(context.Background(), pod)
	if err != nil {
		t.Errorf("expected delete to be allowed, got error: %v", err)
	}
}

func TestValidateCreate_NonPodObject(t *testing.T) {
	validator := newValidator()
	ctx := ctxWithUser("user@redhat.com")

	notAPod := &corev1.Service{}
	_, err := validator.ValidateCreate(ctx, notAPod)
	if err == nil {
		t.Error("expected error for non-Pod object")
	}
}

func TestProtectedIdentity_ExpectedCreator(t *testing.T) {
	identity := ProtectedIdentity{
		Namespace:          "my-ns",
		ServiceAccountName: "my-sa",
	}
	expected := "system:serviceaccount:my-ns:my-sa"
	if got := identity.ExpectedCreator(); got != expected {
		t.Errorf("ExpectedCreator() = %q, want %q", got, expected)
	}
}
