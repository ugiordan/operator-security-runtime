package rbacscope

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ClusterRBACScoper dynamically creates and deletes cluster-scoped ClusterRoles
// and ClusterRoleBindings so that the operator ServiceAccount can access
// cluster-wide resources tied to CR lifecycle. Unlike RBACScoper, it uses
// annotation-based ownership exclusively because ClusterRoles are
// cluster-scoped and cannot have OwnerReferences pointing to namespaced resources.
type ClusterRBACScoper struct {
	client              client.Client
	operatorName        string
	operatorSAName      string
	operatorSANamespace string
	rules               []rbacv1.PolicyRule
	// config holds scope options. Currently only used for forward compatibility;
	// deniedNamespaces does not apply to cluster-scoped resources.
	config              scopeConfig
	ownerTracker        annotationOwnerTracker
}

// NewClusterRBACScoper creates a validated ClusterRBACScoper. All required
// parameters are validated up front; if any are invalid the constructor
// returns an error.
func NewClusterRBACScoper(
	cl client.Client,
	identity OperatorIdentity,
	allowed AllowedRules,
	opts ...Option,
) (*ClusterRBACScoper, error) {
	cfg, rules, err := validateCoreInputs(cl, identity, allowed, opts)
	if err != nil {
		return nil, err
	}
	if allowed.allowAll {
		ctrl.Log.Info("ClusterRBACScoper created with AllowAllRules - no ceiling enforcement",
			"operatorName", identity.Name)
	}
	return &ClusterRBACScoper{
		client:              cl,
		operatorName:        identity.Name,
		operatorSAName:      identity.ServiceAccount,
		operatorSANamespace: identity.Namespace,
		rules:               rules,
		config:              cfg,
		ownerTracker:        annotationOwnerTracker{annotationKey: ownerAnnotationKey},
	}, nil
}

func (s *ClusterRBACScoper) clusterRoleName() string {
	return fmt.Sprintf("%s-cluster-scoped-access", s.operatorName)
}

func (s *ClusterRBACScoper) clusterRoleBindingName() string {
	return fmt.Sprintf("%s-cluster-scoped-access-binding", s.operatorName)
}

func (s *ClusterRBACScoper) labels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": s.operatorName,
		"app.kubernetes.io/component":  "cluster-rbac-scoper",
	}
}

// EnsureClusterAccess creates/updates a ClusterRole and ClusterRoleBinding
// for the operator's ServiceAccount. Uses annotation-based ownership
// (ClusterRoles are cluster-scoped, OwnerReferences require same-namespace).
func (s *ClusterRBACScoper) EnsureClusterAccess(ctx context.Context, owner client.Object) error {
	log := ctrl.LoggerFrom(ctx)

	if owner.GetNamespace() == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	if err := s.ensureClusterRoleWithOwnership(ctx, owner); err != nil {
		return fmt.Errorf("ensuring ClusterRole: %w", err)
	}
	log.Info("ensured ClusterRole", "clusterRole", s.clusterRoleName())

	if err := s.ensureClusterRoleBindingWithOwnership(ctx, owner); err != nil {
		return fmt.Errorf("ensuring ClusterRoleBinding: %w", err)
	}
	log.Info("ensured ClusterRoleBinding", "clusterRoleBinding", s.clusterRoleBindingName())

	return nil
}

// ensureClusterRoleWithOwnership creates or updates a ClusterRole with the
// configured rules and annotation-based ownership.
func (s *ClusterRBACScoper) ensureClusterRoleWithOwnership(
	ctx context.Context,
	owner client.Object,
) error {
	log := ctrl.LoggerFrom(ctx)
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.clusterRoleName(),
		},
	}
	result, err := controllerutil.CreateOrUpdate(ctx, s.client, cr, func() error {
		cr.Labels = s.labels()
		cr.Rules = make([]rbacv1.PolicyRule, len(s.rules))
		for i := range s.rules {
			cr.Rules[i] = *s.rules[i].DeepCopy()
		}
		return s.ownerTracker.addOwner(cr, owner)
	})
	if err != nil {
		return fmt.Errorf("reconciling ClusterRole %s: %w", s.clusterRoleName(), err)
	}
	log.Info("scoped ClusterRole reconciled", "clusterRole", s.clusterRoleName(), "result", result)
	return nil
}

// ensureClusterRoleBindingWithOwnership creates or updates a ClusterRoleBinding
// referencing the ClusterRole and the operator's ServiceAccount. Includes drift
// recovery for immutable RoleRef changes.
func (s *ClusterRBACScoper) ensureClusterRoleBindingWithOwnership(
	ctx context.Context,
	owner client.Object,
) error {
	log := ctrl.LoggerFrom(ctx)
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.clusterRoleBindingName(),
		},
	}
	mutateFn := func() error {
		crb.Labels = s.labels()
		crb.Subjects = []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      s.operatorSAName,
			Namespace: s.operatorSANamespace,
		}}
		crb.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     s.clusterRoleName(),
		}
		return s.ownerTracker.addOwner(crb, owner)
	}
	result, err := controllerutil.CreateOrUpdate(ctx, s.client, crb, mutateFn)
	if err != nil {
		// Handle RoleRef immutability: if someone changed RoleRef externally,
		// delete and recreate the ClusterRoleBinding.
		if apierrors.IsInvalid(err) {
			log.Info("ClusterRoleBinding has drifted RoleRef, recreating")
			if delErr := s.client.Delete(ctx, crb); delErr != nil && !apierrors.IsNotFound(delErr) {
				return fmt.Errorf("deleting stale ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), delErr)
			}
			// Reset crb for recreation; mutateFn captures crb by pointer
			// so it will populate the new object correctly.
			crb = &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: s.clusterRoleBindingName(),
				},
			}
			result, err = controllerutil.CreateOrUpdate(ctx, s.client, crb, mutateFn)
			if err != nil {
				return fmt.Errorf("recreating ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), err)
			}
		} else {
			return fmt.Errorf("reconciling ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), err)
		}
	}
	log.Info("scoped ClusterRoleBinding reconciled", "clusterRoleBinding", s.clusterRoleBindingName(), "result", result)
	return nil
}

// CleanupClusterAccess removes the owner's annotation from the ClusterRole
// and ClusterRoleBinding. Deletes if no owners remain.
// This is the cluster-scoped equivalent of RBACScoper.CleanupAllAccess;
// because ClusterRBACScoper manages a single ClusterRole/ClusterRoleBinding
// pair per operator, no listing is needed.
func (s *ClusterRBACScoper) CleanupClusterAccess(ctx context.Context, owner client.Object) error {
	if owner.GetNamespace() == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	// Clean up ClusterRole first, then ClusterRoleBinding. If ClusterRole
	// deletion succeeds but ClusterRoleBinding fails, the orphaned binding
	// references a non-existent role and grants no permissions — the safer
	// failure mode compared to the reverse order.
	if err := s.cleanupClusterResource(ctx, &rbacv1.ClusterRole{},
		types.NamespacedName{Name: s.clusterRoleName()},
		owner, "ClusterRole"); err != nil {
		return err
	}
	return s.cleanupClusterResource(ctx, &rbacv1.ClusterRoleBinding{},
		types.NamespacedName{Name: s.clusterRoleBindingName()},
		owner, "ClusterRoleBinding")
}

// cleanupClusterResource removes the owner's annotation from the given
// cluster-scoped resource. If no annotation owners remain, the resource
// is deleted entirely.
func (s *ClusterRBACScoper) cleanupClusterResource(
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
		return fmt.Errorf("getting %s %s: %w", kind, key.Name, err)
	}

	s.ownerTracker.removeOwner(obj, owner)

	if !s.ownerTracker.hasOwners(obj) {
		if err := s.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting %s %s: %w", kind, key.Name, err)
		}
		log.Info("deleted scoped "+kind+" (no owners remain)", "name", key.Name)
		return nil
	}

	if err := s.client.Update(ctx, obj); err != nil {
		return fmt.Errorf("updating %s %s to remove owner: %w", kind, key.Name, err)
	}
	log.Info("removed owner annotation from "+kind+" (other owners remain)", "name", key.Name)
	return nil
}
