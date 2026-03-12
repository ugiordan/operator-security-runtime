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

// ClusterRBACScoper dynamically creates and deletes cluster-scoped ClusterRoles
// and ClusterRoleBindings so that the operator ServiceAccount can access
// cluster-wide resources tied to CR lifecycle.
//
// Ownership strategy depends on the owner's scope and whether WithScheme was provided:
//   - Cluster-scoped owner + WithScheme: OwnerReferences (native K8s GC)
//   - Cluster-scoped owner without WithScheme: annotation-based ownership
//   - Namespace-scoped owner: annotation-based ownership (K8s rejects
//     OwnerReferences from namespace-scoped to cluster-scoped resources)
//
// ClusterRBACScoper is safe for concurrent use by multiple goroutines. All
// fields are immutable after construction; methods only read struct fields
// and make Kubernetes API calls (which are themselves concurrency-safe).
type ClusterRBACScoper struct {
	client              client.Client
	scheme              *runtime.Scheme
	operatorName        string
	operatorSAName      string
	operatorSANamespace string
	rules               []rbacv1.PolicyRule
	ownerTracker        annotationOwnerTracker
}

// NewClusterRBACScoper creates a validated ClusterRBACScoper. All required
// parameters are validated up front; if any are invalid the constructor
// returns an error.
//
// Unlike NewRBACScoper (where scheme is a required parameter for same-namespace
// OwnerReferences), ClusterRBACScoper only needs a scheme when
// OwnerReference-based ownership for cluster-scoped owners is desired.
// Pass WithScheme(scheme) to enable this — both owner and ClusterRole are
// cluster-scoped, so Kubernetes allows native OwnerReferences and automatic
// garbage collection. Without WithScheme, annotation-based ownership is used
// for all owners.
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

	if allowed.deferToStatic {
		ctrl.Log.Info("ClusterRBACScoper created with DeferToStaticRBAC - no ceiling enforcement",
			"operatorName", identity.Name)
	}

	if cfg.deniedNamespacesModified {
		ctrl.Log.Info("ClusterRBACScoper: WithDeniedNamespaces/WithAdditionalDeniedNamespaces "+
			"options have no effect on cluster-scoped resources",
			"operatorName", identity.Name)
	}

	return &ClusterRBACScoper{
		client:              cl,
		scheme:              cfg.scheme,
		operatorName:        identity.Name,
		operatorSAName:      identity.ServiceAccount,
		operatorSANamespace: identity.Namespace,
		rules:               rules,
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

// ownershipFn returns the appropriate ownership function for the given owner.
// Cluster-scoped owners with a scheme use OwnerReferences (native K8s GC).
// All other cases use annotation-based ownership.
func (s *ClusterRBACScoper) ownershipFn(owner client.Object) func(obj client.Object, o client.Object) error {
	if s.useOwnerReferences(owner) {
		return func(controlled client.Object, owner client.Object) error {
			return controllerutil.SetOwnerReference(owner, controlled, s.scheme)
		}
	}
	return func(controlled client.Object, owner client.Object) error {
		return s.ownerTracker.addOwner(controlled, owner)
	}
}

// useOwnerReferences returns true when the owner is cluster-scoped and a scheme
// is available, meaning Kubernetes-native OwnerReferences can be used.
func (s *ClusterRBACScoper) useOwnerReferences(owner client.Object) bool {
	return owner.GetNamespace() == "" && s.scheme != nil
}

// EnsureAccess creates/updates a ClusterRole and ClusterRoleBinding for the
// operator's ServiceAccount.
//
// Both namespace-scoped and cluster-scoped owners are accepted:
//   - Cluster-scoped owner + WithScheme: OwnerReferences (native K8s GC)
//   - Cluster-scoped owner without WithScheme: annotation-based ownership
//   - Namespace-scoped owner: annotation-based ownership
func (s *ClusterRBACScoper) EnsureAccess(ctx context.Context, owner client.Object) error {
	setOwnership := s.ownershipFn(owner)

	if err := s.ensureClusterRoleWithOwnership(ctx, owner, setOwnership); err != nil {
		return fmt.Errorf("ensuring ClusterRole: %w", err)
	}

	if err := s.ensureClusterRoleBindingWithOwnership(ctx, owner, setOwnership); err != nil {
		return fmt.Errorf("ensuring ClusterRoleBinding: %w", err)
	}

	return nil
}

// ensureClusterRoleWithOwnership creates or updates a ClusterRole with the
// configured rules and the provided ownership function.
func (s *ClusterRBACScoper) ensureClusterRoleWithOwnership(
	ctx context.Context,
	owner client.Object,
	setOwnership func(obj client.Object, owner client.Object) error,
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
		return setOwnership(cr, owner)
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
	setOwnership func(obj client.Object, owner client.Object) error,
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
		return setOwnership(crb, owner)
	}

	result, err := controllerutil.CreateOrUpdate(ctx, s.client, crb, mutateFn)
	if err == nil {
		log.Info("scoped ClusterRoleBinding reconciled", "clusterRoleBinding", s.clusterRoleBindingName(), "result", result)
		return nil
	}

	// Handle RoleRef immutability: if someone changed RoleRef externally,
	// delete and recreate the ClusterRoleBinding.
	if !apierrors.IsInvalid(err) {
		return fmt.Errorf("reconciling ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), err)
	}

	log.Info("ClusterRoleBinding has drifted RoleRef, recreating")

	if delErr := s.client.Delete(ctx, crb); delErr != nil && !apierrors.IsNotFound(delErr) {
		return fmt.Errorf("deleting stale ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), delErr)
	}

	crb = &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.clusterRoleBindingName(),
		},
	}

	result, err = controllerutil.CreateOrUpdate(ctx, s.client, crb, mutateFn)
	if err != nil {
		return fmt.Errorf("recreating ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), err)
	}

	log.Info("scoped ClusterRoleBinding reconciled", "clusterRoleBinding", s.clusterRoleBindingName(), "result", result)
	return nil
}

// CleanupAccess removes the owner from the ClusterRole and ClusterRoleBinding.
// Deletes if no owners remain.
//
// Both namespace-scoped and cluster-scoped owners are accepted. The cleanup
// strategy mirrors the ownership strategy used during EnsureAccess:
//   - Cluster-scoped owner + WithScheme: removes OwnerReferences
//   - All other cases: removes annotation entries
func (s *ClusterRBACScoper) CleanupAccess(ctx context.Context, owner client.Object) error {
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

// cleanupClusterResource removes the owner from the given cluster-scoped
// resource. Uses OwnerReferences for cluster-scoped owners (when scheme is
// available), annotations otherwise. Deletes the resource if no owners remain.
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

	// Remove ownership via both mechanisms — the resource might have been
	// created with either strategy (e.g., after a WithScheme configuration change).
	removeOwnerRef(obj, owner)
	s.ownerTracker.removeOwner(obj, owner)

	hasOwnerRefs := len(obj.GetOwnerReferences()) > 0
	hasAnnotationOwners := s.ownerTracker.hasOwners(obj)

	if !hasOwnerRefs && !hasAnnotationOwners {
		if err := s.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting %s %s: %w", kind, key.Name, err)
		}
		log.Info("deleted scoped "+kind+" (no owners remain)", "name", key.Name)
		return nil
	}

	if err := s.client.Update(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("resource already deleted during cleanup", "kind", kind, "name", key.Name)
			return nil
		}
		return fmt.Errorf("updating %s %s to remove owner: %w", kind, key.Name, err)
	}

	log.Info("removed owner from "+kind+" (other owners remain)",
		"name", key.Name,
		"remainingOwnerRefs", len(obj.GetOwnerReferences()),
		"hasAnnotationOwners", hasAnnotationOwners)
	return nil
}

// GarbageCollectOrphanedOwners checks the single ClusterRole and
// ClusterRoleBinding managed by this scoper, resolves each annotation
// owner entry against the resolver, and removes entries for owners that
// no longer exist. Resources with no remaining owners are deleted.
//
// When WithScheme is configured, OwnerReferences are also checked before
// deletion (a resource with valid OwnerReferences is not deleted even if
// all annotation entries are removed).
//
// Call this periodically (e.g., on a timer or during leader election start)
// to clean up stale entries left by force-deleted CRs or controller crashes.
func (s *ClusterRBACScoper) GarbageCollectOrphanedOwners(
	ctx context.Context,
	resolver OwnerResolver,
) (GCResult, error) {
	if resolver == nil {
		return GCResult{}, fmt.Errorf("resolver must not be nil")
	}

	var result GCResult
	checkOwnerRefs := s.scheme != nil

	// GC ClusterRole
	cr := &rbacv1.ClusterRole{}
	if err := s.client.Get(ctx, types.NamespacedName{Name: s.clusterRoleName()}, cr); err != nil {
		if !apierrors.IsNotFound(err) {
			return result, fmt.Errorf("getting ClusterRole %s: %w", s.clusterRoleName(), err)
		}
	} else {
		result.ResourcesScanned++
		removed, deleted, err := gcAnnotationOwnersShared(
			ctx, s.client, cr, s.ownerTracker.annotationKey, resolver, "ClusterRole", checkOwnerRefs)
		if err != nil {
			return result, err
		}
		result.EntriesRemoved += removed
		if deleted {
			result.ResourcesDeleted++
		}
	}

	// GC ClusterRoleBinding
	crb := &rbacv1.ClusterRoleBinding{}
	if err := s.client.Get(ctx, types.NamespacedName{Name: s.clusterRoleBindingName()}, crb); err != nil {
		if !apierrors.IsNotFound(err) {
			return result, fmt.Errorf("getting ClusterRoleBinding %s: %w", s.clusterRoleBindingName(), err)
		}
	} else {
		result.ResourcesScanned++
		removed, deleted, err := gcAnnotationOwnersShared(
			ctx, s.client, crb, s.ownerTracker.annotationKey, resolver, "ClusterRoleBinding", checkOwnerRefs)
		if err != nil {
			return result, err
		}
		result.EntriesRemoved += removed
		if deleted {
			result.ResourcesDeleted++
		}
	}

	return result, nil
}
