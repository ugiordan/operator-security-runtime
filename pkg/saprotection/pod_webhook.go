package saprotection

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// ExampleOperatorServiceAccountName is an example SA name for testing and demos.
	// Production operators must provide their own ServiceAccount name via explicit
	// configuration (e.g., environment variables). Do not use this in production.
	ExampleOperatorServiceAccountName = "example-operator-controller-manager"

	// ExampleOperatorNamespace is an example namespace for testing and demos.
	// Production operators must provide their own namespace via explicit
	// configuration (e.g., the downward API). Do not use this in production.
	ExampleOperatorNamespace = "example-operator-system"
)

// ProtectedIdentity represents a ServiceAccount that the webhook protects
// from unauthorized usage by non-operator entities.
type ProtectedIdentity struct {
	// Namespace is the namespace where the operator ServiceAccount lives.
	Namespace string
	// ServiceAccountName is the name of the operator's ServiceAccount.
	ServiceAccountName string
}

// ExpectedCreator returns the fully qualified Kubernetes identity string
// for this ServiceAccount: system:serviceaccount:<namespace>:<name>.
func (p ProtectedIdentity) ExpectedCreator() string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", p.Namespace, p.ServiceAccountName)
}

// SetupPodWebhookWithManager registers the webhook for Pod in the manager.
func SetupPodWebhookWithManager(mgr ctrl.Manager, identities []ProtectedIdentity) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&corev1.Pod{}).
		WithValidator(&PodCustomValidator{ProtectedIdentities: identities}).
		Complete()
}

// +kubebuilder:webhook:path=/validate--v1-pod,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=pods,verbs=create;update,versions=v1,name=vpod-v1.kb.io,admissionReviewVersions=v1

// PodCustomValidator validates Pod create/update requests to prevent
// unauthorized use of protected operator ServiceAccounts.
//
// Security design notes:
//   - Projected serviceAccountToken volume sources always bind to the pod's own
//     ServiceAccount. Kubernetes does not allow projecting tokens for a different SA
//     via the pod spec. Therefore, checking ServiceAccountName alone is sufficient
//     at the pod admission level.
//   - TokenRequest API abuse (minting tokens directly) is a separate attack vector
//     that must be addressed via RBAC restrictions on the serviceaccounts/token
//     subresource in the operator's namespace, not at the webhook level.
//   - This webhook relies on standard Kubernetes ordering: mutating webhooks run
//     before validating webhooks. If a mutating webhook modifies serviceAccountName
//     after this validation, it would not be caught unless reinvocation is enabled.
//
// +kubebuilder:object:generate=false
type PodCustomValidator struct {
	// ProtectedIdentities is the list of ServiceAccount identities that this
	// webhook protects. Only the ServiceAccount's own identity is allowed to
	// create pods that reference it.
	ProtectedIdentities []ProtectedIdentity
}

var _ webhook.CustomValidator = &PodCustomValidator{}

// ValidateCreate checks whether the pod creator is authorized to use any
// protected ServiceAccount. Only the ServiceAccount's own identity is
// allowed to create pods that reference it.
func (v *PodCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object but got %T", obj)
	}

	return v.validateServiceAccountUsage(ctx, pod)
}

// ValidateUpdate checks whether ServiceAccount usage in pod updates is authorized.
// While Kubernetes generally makes the serviceAccountName field immutable after
// creation, we validate updates as defense-in-depth. Short-circuits when the
// ServiceAccount has not changed to avoid unnecessary overhead on kubelet status updates.
func (v *PodCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldPod, ok := oldObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object for oldObj but got %T", oldObj)
	}
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected a Pod object for newObj but got %T", newObj)
	}

	// Short-circuit: ServiceAccountName is immutable after creation.
	// Skip validation if unchanged to avoid overhead on frequent kubelet status updates.
	if oldPod.Spec.ServiceAccountName == newPod.Spec.ServiceAccountName {
		return nil, nil
	}

	return v.validateServiceAccountUsage(ctx, newPod)
}

// ValidateDelete is a no-op. Deletion does not pose a ServiceAccount hijacking risk.
func (v *PodCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validateServiceAccountUsage is the core validation logic. It checks whether
// the requesting identity is authorized to create/update a pod that references
// any protected ServiceAccount.
func (v *PodCustomValidator) validateServiceAccountUsage(ctx context.Context, pod *corev1.Pod) (admission.Warnings, error) {
	log := ctrl.LoggerFrom(ctx).WithName("pod-webhook")

	// Kubernetes normalizes ServiceAccountName and DeprecatedServiceAccount to be
	// consistent before the webhook sees the request. Checking ServiceAccountName
	// alone would suffice; the fallback to DeprecatedServiceAccount is defense-in-depth
	// for edge cases where normalization might not have occurred.
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = pod.Spec.DeprecatedServiceAccount //nolint:staticcheck // check legacy field too
	}

	// Find the matching protected identity, if any
	identity, found := v.findProtectedIdentity(saName)
	if !found {
		// Pod is not using a protected ServiceAccount, allow it
		return nil, nil
	}

	// Extract the admission request to identify WHO is making this request
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		log.Error(err, "failed to get admission request from context")
		// Fail-secure: if we can't identify the caller, deny the request
		return nil, fmt.Errorf("unable to identify request creator; denying as a precaution: %w", err)
	}

	creator := req.UserInfo.Username
	expectedCreator := identity.ExpectedCreator()

	log.Info("validating pod ServiceAccount usage",
		"pod", pod.Name,
		"namespace", pod.Namespace,
		"serviceAccount", saName,
		"creator", creator)

	if creator == expectedCreator {
		log.Info("allowing operator to use its own ServiceAccount",
			"pod", pod.Name,
			"creator", creator)
		return nil, nil
	}

	// Deny all other creators, including cluster-admins (defense-in-depth).
	log.Info("DENIED: unauthorized ServiceAccount usage attempt",
		"pod", pod.Name,
		"namespace", pod.Namespace,
		"serviceAccount", saName,
		"creator", creator,
		"creatorGroups", req.UserInfo.Groups)

	return nil, fmt.Errorf(
		"unauthorized: pods may not use ServiceAccount %q unless created by the operator itself; "+
			"request was made by %q",
		saName, creator)
}

// findProtectedIdentity checks if the given ServiceAccount name matches any
// of the configured protected identities.
//
// Design note: This matches on ServiceAccountName alone (not namespace+name).
// This is intentional defense-in-depth: if an attacker creates a SA with the same
// name as the operator's SA in a different namespace, the webhook still blocks
// unauthorized pod creation using that name. The Namespace field in ProtectedIdentity
// is used solely to construct the expected creator identity string, not to scope
// which namespaces the protection applies to.
func (v *PodCustomValidator) findProtectedIdentity(saName string) (ProtectedIdentity, bool) {
	for _, identity := range v.ProtectedIdentities {
		if identity.ServiceAccountName == saName {
			return identity, true
		}
	}
	return ProtectedIdentity{}, false
}
