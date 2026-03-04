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
	ownerTracker        annotationOwnerTracker
}

// NewRBACScoper creates a validated RBACScoper. All required parameters are
// validated up front; if any are invalid the constructor returns an error.
// The scheme parameter is required because RBACScoper uses OwnerReferences
// for same-namespace resources, and SetOwnerReference needs the scheme to
// look up the owner's GVK. ClusterRBACScoper does not need scheme because
// it uses annotation-based ownership exclusively.
func NewRBACScoper(
	cl client.Client,
	scheme *runtime.Scheme,
	identity OperatorIdentity,
	allowed AllowedRules,
	opts ...Option,
) (*RBACScoper, error) {
	if scheme == nil {
		return nil, fmt.Errorf("scheme must not be nil")
	}
	cfg, rules, err := validateCoreInputs(cl, identity, allowed, opts)
	if err != nil {
		return nil, err
	}
	if allowed.allowAll {
		ctrl.Log.Info("RBACScoper created with DeferToStaticRBAC - no ceiling enforcement",
			"operatorName", identity.Name)
	}
	return &RBACScoper{
		client:              cl,
		scheme:              scheme,
		operatorName:        identity.Name,
		operatorSAName:      identity.ServiceAccount,
		operatorSANamespace: identity.Namespace,
		rules:               rules,
		config:              cfg,
		ownerTracker:        annotationOwnerTracker{annotationKey: ownerAnnotationKey},
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
// Note: DeniedNamespace checks are NOT applied here because the CR's
// existence in its own namespace implies the operator has legitimate reasons
// to access resources there. DeniedNamespace enforcement applies only to
// cross-namespace grants via EnsureAccessInNamespace.
func (s *RBACScoper) EnsureAccess(ctx context.Context, owner client.Object) error {
	log := ctrl.LoggerFrom(ctx)
	ns := owner.GetNamespace()

	if ns == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	ownerRefFn := func(obj client.Object, o client.Object) error {
		return controllerutil.SetOwnerReference(o, obj, s.scheme)
	}

	if err := s.ensureRoleWithOwnership(ctx, owner, ns, ownerRefFn); err != nil {
		return fmt.Errorf("ensuring Role in namespace %s: %w", ns, err)
	}
	log.Info("ensured Role", "namespace", ns, "role", s.roleName())

	if err := s.ensureRoleBindingWithOwnership(ctx, owner, ns, ownerRefFn); err != nil {
		return fmt.Errorf("ensuring RoleBinding in namespace %s: %w", ns, err)
	}
	log.Info("ensured RoleBinding", "namespace", ns, "roleBinding", s.roleBindingName())

	return nil
}

// ensureRoleWithOwnership creates or updates a Role in ns, using the provided
// setOwnership function to set either OwnerReferences (same-namespace) or
// annotation-based ownership (cross-namespace).
func (s *RBACScoper) ensureRoleWithOwnership(
	ctx context.Context,
	owner client.Object,
	ns string,
	setOwnership func(obj client.Object, owner client.Object) error,
) error {
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
		return setOwnership(role, owner)
	})
	if err != nil {
		return fmt.Errorf("reconciling Role %s/%s: %w", ns, s.roleName(), err)
	}
	log.Info("scoped Role reconciled", "namespace", ns, "role", s.roleName(), "result", result)
	return nil
}

// ensureRoleBindingWithOwnership creates or updates a RoleBinding in ns,
// using the provided setOwnership function. Includes drift recovery for
// immutable RoleRef changes.
func (s *RBACScoper) ensureRoleBindingWithOwnership(
	ctx context.Context,
	owner client.Object,
	ns string,
	setOwnership func(obj client.Object, owner client.Object) error,
) error {
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
		return setOwnership(rb, owner)
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
				return fmt.Errorf("recreating RoleBinding %s/%s: %w", ns, s.roleBindingName(), err)
			}
		} else {
			return fmt.Errorf("reconciling RoleBinding %s/%s: %w", ns, s.roleBindingName(), err)
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
// resource. If no owners remain (neither OwnerReferences nor annotation
// entries), the resource is deleted entirely.
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

	// Check both ownership mechanisms: the resource might also have
	// cross-namespace annotation owners from EnsureAccessInNamespace.
	hasOwnerRefs := len(obj.GetOwnerReferences()) > 0
	hasAnnotationOwners := s.ownerTracker.hasOwners(obj)

	if !hasOwnerRefs && !hasAnnotationOwners {
		if err := s.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting %s %s: %w", kind, key, err)
		}
		log.Info("deleted scoped "+kind+" (no owners remain)", "namespace", key.Namespace)
		return nil
	}

	if err := s.client.Update(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("resource already deleted during cleanup", "kind", kind, "namespace", key.Namespace)
			return nil
		}
		return fmt.Errorf("updating %s %s to remove owner: %w", kind, key, err)
	}
	log.Info("removed OwnerReference from "+kind+" (other owners remain)",
		"namespace", key.Namespace, "remainingOwners", len(obj.GetOwnerReferences()),
		"hasAnnotationOwners", hasAnnotationOwners)
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

// CleanupAccessInNamespace removes the owner's references from the Role
// and RoleBinding in targetNS. If targetNS equals the owner's namespace,
// delegates to CleanupAccess (OwnerReference-based). Otherwise, uses
// annotation-based ownership removal. Deletes resources if no owners remain.
func (s *RBACScoper) CleanupAccessInNamespace(
	ctx context.Context,
	owner client.Object,
	targetNS string,
) error {
	if owner.GetNamespace() == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}
	if targetNS == "" {
		return fmt.Errorf("targetNS must not be empty")
	}

	// Same-namespace: delegate to CleanupAccess (OwnerReference-based)
	if targetNS == owner.GetNamespace() {
		return s.CleanupAccess(ctx, owner)
	}

	// Cross-namespace: use Get-based cleanup with annotation ownership
	roleKey := types.NamespacedName{Name: s.roleName(), Namespace: targetNS}
	role := &rbacv1.Role{}
	if err := s.cleanupCrossNSResource(ctx, role, roleKey, owner, "Role"); err != nil {
		return err
	}

	rbKey := types.NamespacedName{Name: s.roleBindingName(), Namespace: targetNS}
	rb := &rbacv1.RoleBinding{}
	return s.cleanupCrossNSResource(ctx, rb, rbKey, owner, "RoleBinding")
}

// cleanupCrossNSResource fetches a resource by key and delegates to
// cleanupManagedResource for ownership removal and conditional deletion.
// Returns nil if the resource is not found.
func (s *RBACScoper) cleanupCrossNSResource(
	ctx context.Context,
	obj client.Object,
	key types.NamespacedName,
	owner client.Object,
	kind string,
) error {
	if err := s.client.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("getting %s %s: %w", kind, key, err)
	}
	return s.cleanupManagedResource(ctx, obj, owner, &s.ownerTracker, kind)
}

// EnsureAccessInNamespace creates/updates a Role and RoleBinding in
// targetNS for the owner. Uses annotation-based ownership because
// cross-namespace OwnerReferences are not supported by Kubernetes.
// If targetNS is the same as the owner's namespace, this delegates
// to EnsureAccess (which uses OwnerReferences).
func (s *RBACScoper) EnsureAccessInNamespace(
	ctx context.Context,
	owner client.Object,
	targetNS string,
) error {
	log := ctrl.LoggerFrom(ctx)

	if owner.GetNamespace() == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	if targetNS == "" {
		return fmt.Errorf("targetNS must not be empty")
	}

	// If targetNS is the owner's namespace, delegate to EnsureAccess (uses OwnerReferences).
	// This must be checked before the denied namespace check so that
	// EnsureAccessInNamespace(ctx, cr, cr.GetNamespace()) behaves identically
	// to EnsureAccess(ctx, cr), including not rejecting the owner's own namespace.
	if targetNS == owner.GetNamespace() {
		return s.EnsureAccess(ctx, owner)
	}

	if s.isDeniedNamespace(targetNS) {
		return fmt.Errorf("namespace %q is denied by configuration", targetNS)
	}

	annotationFn := func(obj client.Object, o client.Object) error {
		return s.ownerTracker.addOwner(obj, o)
	}

	if err := s.ensureRoleWithOwnership(ctx, owner, targetNS, annotationFn); err != nil {
		return fmt.Errorf("ensuring Role in namespace %s: %w", targetNS, err)
	}
	log.Info("ensured cross-namespace Role", "namespace", targetNS, "role", s.roleName())

	if err := s.ensureRoleBindingWithOwnership(ctx, owner, targetNS, annotationFn); err != nil {
		return fmt.Errorf("ensuring RoleBinding in namespace %s: %w", targetNS, err)
	}
	log.Info("ensured cross-namespace RoleBinding", "namespace", targetNS, "roleBinding", s.roleBindingName())

	return nil
}

// GarbageCollectOrphanedOwners scans all managed Roles and RoleBindings,
// checks each annotation owner entry against the resolver, and removes
// entries for owners that no longer exist. Resources with no remaining
// owners (no OwnerReferences AND no annotation entries) are deleted.
//
// Call this periodically (e.g., on a timer or during leader election start)
// to clean up stale entries left by force-deleted CRs or controller crashes.
func (s *RBACScoper) GarbageCollectOrphanedOwners(
	ctx context.Context,
	resolver OwnerResolver,
) (GCResult, error) {
	var result GCResult

	// GC Roles
	roleList := &rbacv1.RoleList{}
	listOpts := []client.ListOption{
		client.MatchingLabels(s.labels()),
		client.Limit(cleanupListPageSize),
	}
	for {
		if err := s.client.List(ctx, roleList, listOpts...); err != nil {
			return result, fmt.Errorf("listing managed Roles: %w", err)
		}
		for i := range roleList.Items {
			if roleList.Items[i].Name != s.roleName() {
				continue
			}
			result.ResourcesScanned++
			removed, deleted, err := s.gcAnnotationOwners(ctx, &roleList.Items[i], resolver, "Role")
			if err != nil {
				return result, err
			}
			result.EntriesRemoved += removed
			if deleted {
				result.ResourcesDeleted++
			}
		}
		if roleList.Continue == "" {
			break
		}
		listOpts = []client.ListOption{
			client.MatchingLabels(s.labels()),
			client.Limit(cleanupListPageSize),
			client.Continue(roleList.Continue),
		}
	}

	// GC RoleBindings
	rbList := &rbacv1.RoleBindingList{}
	listOpts = []client.ListOption{
		client.MatchingLabels(s.labels()),
		client.Limit(cleanupListPageSize),
	}
	for {
		if err := s.client.List(ctx, rbList, listOpts...); err != nil {
			return result, fmt.Errorf("listing managed RoleBindings: %w", err)
		}
		for i := range rbList.Items {
			if rbList.Items[i].Name != s.roleBindingName() {
				continue
			}
			result.ResourcesScanned++
			removed, deleted, err := s.gcAnnotationOwners(ctx, &rbList.Items[i], resolver, "RoleBinding")
			if err != nil {
				return result, err
			}
			result.EntriesRemoved += removed
			if deleted {
				result.ResourcesDeleted++
			}
		}
		if rbList.Continue == "" {
			break
		}
		listOpts = []client.ListOption{
			client.MatchingLabels(s.labels()),
			client.Limit(cleanupListPageSize),
			client.Continue(rbList.Continue),
		}
	}

	return result, nil
}

// gcAnnotationOwners delegates to the shared GC logic with checkOwnerRefs=true,
// since namespace-scoped resources may have OwnerReferences.
func (s *RBACScoper) gcAnnotationOwners(
	ctx context.Context,
	obj client.Object,
	resolver OwnerResolver,
	kind string,
) (removed int, deleted bool, err error) {
	return gcAnnotationOwnersShared(ctx, s.client, obj, s.ownerTracker.annotationKey, resolver, kind, true)
}

// CleanupAllAccess removes the owner's references from all managed
// Roles and RoleBindings across namespaces. Uses label-selected listing
// to find managed resources. For same-namespace resources, removes
// OwnerReferences. For cross-namespace resources, removes annotation entries.
// Resources with no remaining owners (no OwnerReferences AND no annotation
// entries) are deleted.
func (s *RBACScoper) CleanupAllAccess(ctx context.Context, owner client.Object) error {
	if owner.GetNamespace() == "" {
		return fmt.Errorf("owner must be namespace-scoped; got cluster-scoped resource %s/%s",
			owner.GetObjectKind().GroupVersionKind(), owner.GetName())
	}

	// Cleanup all managed Roles (paginated to limit API server load)
	roleList := &rbacv1.RoleList{}
	listOpts := []client.ListOption{
		client.MatchingLabels(s.labels()),
		client.Limit(cleanupListPageSize),
	}
	for {
		if err := s.client.List(ctx, roleList, listOpts...); err != nil {
			return fmt.Errorf("listing managed Roles: %w", err)
		}
		for i := range roleList.Items {
			if roleList.Items[i].Name != s.roleName() {
				continue
			}
			if err := s.cleanupManagedResource(ctx, &roleList.Items[i], owner, &s.ownerTracker, "Role"); err != nil {
				return err
			}
		}
		if roleList.Continue == "" {
			break
		}
		listOpts = []client.ListOption{
			client.MatchingLabels(s.labels()),
			client.Limit(cleanupListPageSize),
			client.Continue(roleList.Continue),
		}
	}

	// Cleanup all managed RoleBindings (paginated to limit API server load)
	rbList := &rbacv1.RoleBindingList{}
	listOpts = []client.ListOption{
		client.MatchingLabels(s.labels()),
		client.Limit(cleanupListPageSize),
	}
	for {
		if err := s.client.List(ctx, rbList, listOpts...); err != nil {
			return fmt.Errorf("listing managed RoleBindings: %w", err)
		}
		for i := range rbList.Items {
			if rbList.Items[i].Name != s.roleBindingName() {
				continue
			}
			if err := s.cleanupManagedResource(ctx, &rbList.Items[i], owner, &s.ownerTracker, "RoleBinding"); err != nil {
				return err
			}
		}
		if rbList.Continue == "" {
			break
		}
		listOpts = []client.ListOption{
			client.MatchingLabels(s.labels()),
			client.Limit(cleanupListPageSize),
			client.Continue(rbList.Continue),
		}
	}

	return nil
}

// cleanupManagedResource removes the owner from a managed resource.
// For same-namespace resources, removes the OwnerReference.
// For cross-namespace resources, removes the annotation entry.
// If no owners remain (no OwnerReferences AND no annotation entries),
// the resource is deleted.
func (s *RBACScoper) cleanupManagedResource(
	ctx context.Context,
	obj client.Object,
	owner client.Object,
	tracker *annotationOwnerTracker,
	kind string,
) error {
	log := ctrl.LoggerFrom(ctx)

	// Always try both ownership mechanisms: the resource might have been
	// created via either EnsureAccess (OwnerReferences) or
	// EnsureAccessInNamespace (annotations).
	s.removeOwnerRef(obj, owner)
	tracker.removeOwner(obj, owner)

	// Check if any owners remain (either OwnerReferences or annotation entries)
	hasOwnerRefs := len(obj.GetOwnerReferences()) > 0
	hasAnnotationOwners := tracker.hasOwners(obj)

	if !hasOwnerRefs && !hasAnnotationOwners {
		if err := s.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting %s %s/%s: %w", kind, obj.GetNamespace(), obj.GetName(), err)
		}
		log.Info("deleted scoped "+kind+" (no owners remain)", "namespace", obj.GetNamespace())
		return nil
	}

	if err := s.client.Update(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("resource already deleted during cleanup", "kind", kind, "namespace", obj.GetNamespace())
			return nil
		}
		return fmt.Errorf("updating %s %s/%s to remove owner: %w", kind, obj.GetNamespace(), obj.GetName(), err)
	}
	log.Info("removed owner from "+kind+" (other owners remain)",
		"namespace", obj.GetNamespace(),
		"remainingOwnerRefs", len(obj.GetOwnerReferences()),
		"hasAnnotationOwners", hasAnnotationOwners)
	return nil
}
