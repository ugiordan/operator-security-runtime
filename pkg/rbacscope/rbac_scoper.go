package rbacscope

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// RBACScoper dynamically creates and deletes namespace-scoped Roles and
// RoleBindings so that the operator ServiceAccount can access resources only
// in namespaces where a CR exists.
type RBACScoper struct {
	client              client.Client
	scheme              *runtime.Scheme
	operatorName        string
	operatorSAName      string
	operatorSANamespace string
	rules               []rbacv1.PolicyRule
	config              scopeConfig
}

// NewRBACScoper creates a validated RBACScoper. All required parameters are
// validated up front; if any are invalid the constructor returns an error.
func NewRBACScoper(
	cl client.Client,
	scheme *runtime.Scheme,
	identity OperatorIdentity,
	allowed AllowedRules,
	opts ...Option,
) (*RBACScoper, error) {
	if cl == nil {
		return nil, fmt.Errorf("client must not be nil")
	}
	if scheme == nil {
		return nil, fmt.Errorf("scheme must not be nil")
	}
	if identity.Name == "" {
		return nil, fmt.Errorf("OperatorIdentity.Name must not be empty")
	}
	if identity.ServiceAccount == "" {
		return nil, fmt.Errorf("OperatorIdentity.ServiceAccount must not be empty")
	}
	if identity.Namespace == "" {
		return nil, fmt.Errorf("OperatorIdentity.Namespace must not be empty")
	}
	if !allowed.allowAll && len(allowed.rules) == 0 {
		return nil, fmt.Errorf("AllowedRules must not be empty")
	}

	cfg := defaultScopeConfig()
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	var rules []rbacv1.PolicyRule
	if allowed.allowAll {
		rules = nil // will be set per-call
		ctrl.Log.Info("RBACScoper created with AllowAllRules - no ceiling enforcement",
			"operatorName", identity.Name)
	} else {
		rules = make([]rbacv1.PolicyRule, len(allowed.rules))
		for i := range allowed.rules {
			rules[i] = *allowed.rules[i].DeepCopy()
		}
	}

	return &RBACScoper{
		client:              cl,
		scheme:              scheme,
		operatorName:        identity.Name,
		operatorSAName:      identity.ServiceAccount,
		operatorSANamespace: identity.Namespace,
		rules:               rules,
		config:              cfg,
	}, nil
}

func (s *RBACScoper) roleName() string {
	return fmt.Sprintf("%s-scoped-access", s.operatorName)
}

func (s *RBACScoper) roleBindingName() string {
	return fmt.Sprintf("%s-scoped-access-binding", s.operatorName)
}

func (s *RBACScoper) labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": s.operatorName,
		"app.kubernetes.io/component":  "rbac-scoper",
	}
}

// EnsureAccess creates or updates a Role and RoleBinding in the owner's
// namespace so that the operator ServiceAccount has the configured access there.
func (s *RBACScoper) EnsureAccess(ctx context.Context, owner client.Object) error {
	log := ctrl.LoggerFrom(ctx)
	ns := owner.GetNamespace()

	if ns == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	if err := s.ensureRole(ctx, owner, ns); err != nil {
		return fmt.Errorf("ensuring Role in namespace %s: %w", ns, err)
	}
	log.Info("ensured Role", "namespace", ns, "role", s.roleName())

	if err := s.ensureRoleBinding(ctx, owner, ns); err != nil {
		return fmt.Errorf("ensuring RoleBinding in namespace %s: %w", ns, err)
	}
	log.Info("ensured RoleBinding", "namespace", ns, "roleBinding", s.roleBindingName())

	return nil
}

func (s *RBACScoper) ensureRole(ctx context.Context, owner client.Object, ns string) error {
	log := ctrl.LoggerFrom(ctx)
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.roleName(),
			Namespace: ns,
		},
	}
	result, err := controllerutil.CreateOrUpdate(ctx, s.client, role, func() error {
		role.Labels = s.labels()
		role.Rules = make([]rbacv1.PolicyRule, len(s.rules))
		for i := range s.rules {
			role.Rules[i] = *s.rules[i].DeepCopy()
		}
		// Append this CR as an owner (does not overwrite existing owners)
		return controllerutil.SetOwnerReference(owner, role, s.scheme)
	})
	if err != nil {
		return fmt.Errorf("failed to %s Role %s/%s: %w", result, ns, s.roleName(), err)
	}
	log.Info("scoped Role reconciled", "namespace", ns, "role", s.roleName(), "result", result)
	return nil
}

func (s *RBACScoper) ensureRoleBinding(ctx context.Context, owner client.Object, ns string) error {
	log := ctrl.LoggerFrom(ctx)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.roleBindingName(),
			Namespace: ns,
		},
	}
	mutateFn := func() error {
		rb.Labels = s.labels()
		rb.Subjects = []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      s.operatorSAName,
			Namespace: s.operatorSANamespace,
		}}
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     s.roleName(),
		}
		return controllerutil.SetOwnerReference(owner, rb, s.scheme)
	}
	result, err := controllerutil.CreateOrUpdate(ctx, s.client, rb, mutateFn)
	if err != nil {
		// Handle RoleRef immutability: if someone changed RoleRef externally,
		// delete and recreate the RoleBinding.
		if apierrors.IsInvalid(err) {
			log.Info("RoleBinding has drifted RoleRef, recreating", "namespace", ns)
			if delErr := s.client.Delete(ctx, rb); delErr != nil && !apierrors.IsNotFound(delErr) {
				return fmt.Errorf("deleting stale RoleBinding %s/%s: %w", ns, s.roleBindingName(), delErr)
			}
			// Reset rb for recreation; mutateFn captures rb by pointer
			// so it will populate the new object correctly.
			rb = &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.roleBindingName(),
					Namespace: ns,
				},
			}
			result, err = controllerutil.CreateOrUpdate(ctx, s.client, rb, mutateFn)
			if err != nil {
				return fmt.Errorf("failed to recreate RoleBinding %s/%s: %w", ns, s.roleBindingName(), err)
			}
		} else {
			return fmt.Errorf("failed to %s RoleBinding %s/%s: %w", result, ns, s.roleBindingName(), err)
		}
	}
	log.Info("scoped RoleBinding reconciled", "namespace", ns, "rolebinding", s.roleBindingName(), "result", result)
	return nil
}

// CleanupAccess removes the owner's OwnerReference from the Role and
// RoleBinding in the owner's namespace. If no OwnerReferences remain, the
// Role/RoleBinding is deleted. This ensures that when multiple CRs share a
// namespace, cleanup of one CR does not break the others.
func (s *RBACScoper) CleanupAccess(ctx context.Context, owner client.Object) error {
	ns := owner.GetNamespace()

	if ns == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	if err := s.cleanupOwnedResource(ctx, &rbacv1.Role{},
		types.NamespacedName{Name: s.roleName(), Namespace: ns},
		owner, "Role"); err != nil {
		return err
	}
	return s.cleanupOwnedResource(ctx, &rbacv1.RoleBinding{},
		types.NamespacedName{Name: s.roleBindingName(), Namespace: ns},
		owner, "RoleBinding")
}

// cleanupOwnedResource removes the owner's OwnerReference from the given
// resource. If no OwnerReferences remain after removal, the resource is
// deleted entirely.
func (s *RBACScoper) cleanupOwnedResource(
	ctx context.Context,
	obj client.Object,
	key types.NamespacedName,
	owner client.Object,
	kind string,
) error {
	log := ctrl.LoggerFrom(ctx)
	if err := s.client.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting %s %s: %w", kind, key, err)
	}

	s.removeOwnerRef(obj, owner)
	if len(obj.GetOwnerReferences()) == 0 {
		if err := s.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting %s %s: %w", kind, key, err)
		}
		log.Info("deleted scoped "+kind+" (no owners remain)", "namespace", key.Namespace)
		return nil
	}

	if err := s.client.Update(ctx, obj); err != nil {
		return fmt.Errorf("updating %s %s to remove owner: %w", kind, key, err)
	}
	log.Info("removed OwnerReference from "+kind+" (other owners remain)",
		"namespace", key.Namespace, "remainingOwners", len(obj.GetOwnerReferences()))
	return nil
}

// removeOwnerRef removes the OwnerReference matching the given owner from obj.
func (s *RBACScoper) removeOwnerRef(obj client.Object, owner client.Object) {
	ownerUID := owner.GetUID()
	refs := obj.GetOwnerReferences()
	filtered := make([]metav1.OwnerReference, 0, len(refs))
	for _, ref := range refs {
		if ref.UID != ownerUID {
			filtered = append(filtered, ref)
		}
	}
	obj.SetOwnerReferences(filtered)
}
