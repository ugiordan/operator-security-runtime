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
	Client              client.Client
	Scheme              *runtime.Scheme
	OperatorName        string
	OperatorSAName      string
	OperatorSANamespace string
	Rules               []rbacv1.PolicyRule
}

func (s *RBACScoper) roleName() string {
	return fmt.Sprintf("%s-scoped-access", s.OperatorName)
}

func (s *RBACScoper) roleBindingName() string {
	return fmt.Sprintf("%s-scoped-access-binding", s.OperatorName)
}

func (s *RBACScoper) labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": s.OperatorName,
		"app.kubernetes.io/component":  "rbac-scoper",
	}
}

// validate checks that the RBACScoper is properly configured.
func (s *RBACScoper) validate() error {
	if s.Client == nil {
		return fmt.Errorf("Client must not be nil")
	}
	if s.Scheme == nil {
		return fmt.Errorf("Scheme must not be nil")
	}
	if s.OperatorName == "" {
		return fmt.Errorf("OperatorName must not be empty")
	}
	if s.OperatorSAName == "" {
		return fmt.Errorf("OperatorSAName must not be empty")
	}
	if s.OperatorSANamespace == "" {
		return fmt.Errorf("OperatorSANamespace must not be empty")
	}
	if len(s.Rules) == 0 {
		return fmt.Errorf("Rules must not be empty")
	}
	return nil
}

// EnsureAccess creates or updates a Role and RoleBinding in the owner's
// namespace so that the operator ServiceAccount has the configured access there.
func (s *RBACScoper) EnsureAccess(ctx context.Context, owner client.Object) error {
	if err := s.validate(); err != nil {
		return fmt.Errorf("invalid RBACScoper configuration: %w", err)
	}

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
	result, err := controllerutil.CreateOrUpdate(ctx, s.Client, role, func() error {
		role.Labels = s.labels()
		role.Rules = s.Rules
		// Append this CR as an owner (does not overwrite existing owners)
		return controllerutil.SetOwnerReference(owner, role, s.Scheme)
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
			Name:      s.OperatorSAName,
			Namespace: s.OperatorSANamespace,
		}}
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     s.roleName(),
		}
		return controllerutil.SetOwnerReference(owner, rb, s.Scheme)
	}
	result, err := controllerutil.CreateOrUpdate(ctx, s.Client, rb, mutateFn)
	if err != nil {
		// Handle RoleRef immutability: if someone changed RoleRef externally,
		// delete and recreate the RoleBinding.
		if apierrors.IsInvalid(err) {
			log.Info("RoleBinding has drifted RoleRef, recreating", "namespace", ns)
			if delErr := s.Client.Delete(ctx, rb); delErr != nil && !apierrors.IsNotFound(delErr) {
				return fmt.Errorf("deleting stale RoleBinding %s/%s: %w", ns, s.roleBindingName(), delErr)
			}
			// Reset for recreation
			rb = &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      s.roleBindingName(),
					Namespace: ns,
				},
			}
			result, err = controllerutil.CreateOrUpdate(ctx, s.Client, rb, mutateFn)
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
	if err := s.validate(); err != nil {
		return fmt.Errorf("invalid RBACScoper configuration: %w", err)
	}

	log := ctrl.LoggerFrom(ctx)
	ns := owner.GetNamespace()

	if ns == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	// Remove this CR's OwnerReference from the Role.
	// Only delete if no OwnerReferences remain.
	role := &rbacv1.Role{}
	if err := s.Client.Get(ctx, types.NamespacedName{Name: s.roleName(), Namespace: ns}, role); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("getting Role %s/%s: %w", ns, s.roleName(), err)
		}
		// Already gone, nothing to do
	} else {
		s.removeOwnerRef(role, owner)
		if len(role.OwnerReferences) == 0 {
			// No more owners -- delete the Role
			if err := s.Client.Delete(ctx, role); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("deleting Role %s/%s: %w", ns, s.roleName(), err)
			}
			log.Info("deleted scoped Role (no owners remain)", "namespace", ns)
		} else {
			// Other CRs still need this Role -- just update to remove our OwnerRef
			if err := s.Client.Update(ctx, role); err != nil {
				return fmt.Errorf("updating Role %s/%s to remove owner: %w", ns, s.roleName(), err)
			}
			log.Info("removed OwnerReference from Role (other owners remain)", "namespace", ns, "remainingOwners", len(role.OwnerReferences))
		}
	}

	// Same logic for RoleBinding
	rb := &rbacv1.RoleBinding{}
	if err := s.Client.Get(ctx, types.NamespacedName{Name: s.roleBindingName(), Namespace: ns}, rb); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("getting RoleBinding %s/%s: %w", ns, s.roleBindingName(), err)
		}
	} else {
		s.removeOwnerRef(rb, owner)
		if len(rb.OwnerReferences) == 0 {
			if err := s.Client.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("deleting RoleBinding %s/%s: %w", ns, s.roleBindingName(), err)
			}
			log.Info("deleted scoped RoleBinding (no owners remain)", "namespace", ns)
		} else {
			if err := s.Client.Update(ctx, rb); err != nil {
				return fmt.Errorf("updating RoleBinding %s/%s to remove owner: %w", ns, s.roleBindingName(), err)
			}
			log.Info("removed OwnerReference from RoleBinding (other owners remain)", "namespace", ns, "remainingOwners", len(rb.OwnerReferences))
		}
	}

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
