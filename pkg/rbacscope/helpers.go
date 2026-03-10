package rbacscope

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// dns1123SubdomainRegexp matches valid DNS-1123 subdomain names:
// lowercase alphanumeric, hyphens, and dots; must start and end with alphanumeric.
var dns1123SubdomainRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?$`)

// validateDNS1123Subdomain checks that value is a valid DNS-1123 subdomain
// (as required by Kubernetes resource names). Returns a descriptive error
// if the value is empty, too long, or contains invalid characters.
func validateDNS1123Subdomain(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(value) > 253 {
		return fmt.Errorf("%s must be no more than 253 characters: got %d", field, len(value))
	}
	if !dns1123SubdomainRegexp.MatchString(value) {
		return fmt.Errorf("%s must be a valid DNS-1123 subdomain: got %q", field, value)
	}
	return nil
}

const (
	// ownerAnnotationKey is the annotation used to track cross-namespace owners.
	// Unlike OwnerReferences, annotations can reference objects in other namespaces.
	ownerAnnotationKey = "opendatahub.io/scoped-access-owners"

	// maxAnnotationOwners limits the number of owner entries stored in the
	// annotation to prevent unbounded growth.
	maxAnnotationOwners = 100

	// cleanupListPageSize is the page size used when listing managed resources
	// during CleanupAllAccess. Limits API server load for operators managing
	// many namespaces.
	cleanupListPageSize = 100
)

// annotationOwnerTracker manages annotation-based ownership for resources
// that cannot use OwnerReferences (cross-namespace or cluster-scoped).
//
// Annotations are updated within the mutate function of CreateOrUpdate,
// which uses optimistic concurrency (resourceVersion) to prevent concurrent
// overwrites. SSA with a dedicated FieldOwner would provide stronger
// protection against other controllers, but is not needed currently because
// managed resources use operator-specific names (<operator>-scoped-access)
// that other controllers are unlikely to modify.
//
// Security note: any user with update access to Roles/ClusterRoles can modify
// the ownership annotation, potentially adding fake owners (to prevent cleanup)
// or removing legitimate owners (to trigger premature deletion). This is
// mitigated by the fact that managed resources use operator-specific names
// and modifying RBAC resources already requires elevated privileges. For
// stricter protection, consider using a ValidatingWebhook that restricts
// annotation modifications to the operator's ServiceAccount.
type annotationOwnerTracker struct {
	annotationKey string
}

// ownerKey returns a string key for the given owner: "<namespace>/<name>/<uid>"
func ownerKey(owner client.Object) string {
	return fmt.Sprintf("%s/%s/%s", owner.GetNamespace(), owner.GetName(), string(owner.GetUID()))
}

// addOwner adds the owner to the annotation on obj. If already present, no-op.
// Returns an error if the maximum number of annotation owners would be exceeded.
func (t *annotationOwnerTracker) addOwner(obj client.Object, owner client.Object) error {
	key := ownerKey(owner)
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	existing := annotations[t.annotationKey]
	if existing == "" {
		annotations[t.annotationKey] = key
		obj.SetAnnotations(annotations)
		return nil
	}

	// Parse existing entries, skipping empty/whitespace segments from
	// corrupted annotations. Rebuild from valid entries to prevent
	// corruption from accumulating over successive addOwner calls.
	rawEntries := strings.Split(existing, ",")
	validEntries := make([]string, 0, len(rawEntries))
	for _, entry := range rawEntries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == key {
			return nil // already present
		}
		validEntries = append(validEntries, entry)
	}

	if len(validEntries) >= maxAnnotationOwners {
		return fmt.Errorf("maximum owner count (%d) exceeded for annotation %s", maxAnnotationOwners, t.annotationKey)
	}

	annotations[t.annotationKey] = strings.Join(append(validEntries, key), ",")
	obj.SetAnnotations(annotations)
	return nil
}

// removeOwner removes the owner from the annotation on obj.
func (t *annotationOwnerTracker) removeOwner(obj client.Object, owner client.Object) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return
	}

	existing := annotations[t.annotationKey]
	if existing == "" {
		return
	}

	key := ownerKey(owner)
	entries := strings.Split(existing, ",")
	filtered := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry != key {
			filtered = append(filtered, entry)
		}
	}

	if len(filtered) == 0 {
		delete(annotations, t.annotationKey)
	} else {
		annotations[t.annotationKey] = strings.Join(filtered, ",")
	}
	obj.SetAnnotations(annotations)
}

// hasOwners returns true if the annotation has at least one owner entry.
func (t *annotationOwnerTracker) hasOwners(obj client.Object) bool {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false
	}

	existing := annotations[t.annotationKey]
	for _, entry := range strings.Split(existing, ",") {
		if strings.TrimSpace(entry) != "" {
			return true
		}
	}
	return false
}

// validateCoreInputs validates the common inputs shared by NewRBACScoper and
// NewClusterRBACScoper. Returns the resolved scopeConfig and deep-copied rules.
func validateCoreInputs(
	cl client.Client,
	identity OperatorIdentity,
	allowed AllowedRules,
	opts []Option,
) (scopeConfig, []rbacv1.PolicyRule, error) {
	if cl == nil {
		return scopeConfig{}, nil, fmt.Errorf("client must not be nil")
	}
	if identity.Name == "" {
		return scopeConfig{}, nil, fmt.Errorf("OperatorIdentity.Name must not be empty")
	}
	if identity.ServiceAccount == "" {
		return scopeConfig{}, nil, fmt.Errorf("OperatorIdentity.ServiceAccount must not be empty")
	}
	if identity.Namespace == "" {
		return scopeConfig{}, nil, fmt.Errorf("OperatorIdentity.Namespace must not be empty")
	}
	if err := validateDNS1123Subdomain("OperatorIdentity.Name", identity.Name); err != nil {
		return scopeConfig{}, nil, err
	}
	// Generated resource names append suffixes (longest: "-cluster-scoped-access-binding"
	// = 30 chars). Limit operator name so the total stays within 253.
	const maxOperatorNameLen = 253 - 30 // 223
	if len(identity.Name) > maxOperatorNameLen {
		return scopeConfig{}, nil, fmt.Errorf("OperatorIdentity.Name must be no more than %d characters "+
			"(generated resource names add up to 30 characters): got %d", maxOperatorNameLen, len(identity.Name))
	}
	if err := validateDNS1123Subdomain("OperatorIdentity.ServiceAccount", identity.ServiceAccount); err != nil {
		return scopeConfig{}, nil, err
	}
	if err := validateDNS1123Subdomain("OperatorIdentity.Namespace", identity.Namespace); err != nil {
		return scopeConfig{}, nil, err
	}
	if !allowed.deferToStatic && len(allowed.rules) == 0 {
		return scopeConfig{}, nil, fmt.Errorf("AllowedRules must not be empty")
	}

	cfg := defaultScopeConfig()
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	// Surface deferred errors from option functions.
	if len(cfg.errs) > 0 {
		return scopeConfig{}, nil, cfg.errs[0]
	}

	// Validate that no denied namespace entry is empty.
	for _, ns := range cfg.deniedNamespaces {
		if ns == "" {
			return scopeConfig{}, nil, fmt.Errorf("denied namespace must not be empty")
		}
	}

	var rules []rbacv1.PolicyRule
	if !allowed.deferToStatic {
		rules = make([]rbacv1.PolicyRule, len(allowed.rules))
		for i := range allowed.rules {
			rules[i] = *allowed.rules[i].DeepCopy()
		}
	}
	// When allowed.deferToStatic is true, rules stays nil (no ceiling enforcement).

	return cfg, rules, nil
}

// isDeniedNamespace checks if ns matches any denied namespace pattern.
// Entries ending with "-" are treated as prefix patterns.
func (s *RBACScoper) isDeniedNamespace(ns string) bool {
	for _, denied := range s.config.deniedNamespaces {
		if strings.HasSuffix(denied, "-") {
			// Prefix match: "openshift-" matches "openshift-ingress"
			if strings.HasPrefix(ns, denied) {
				return true
			}
		} else {
			// Exact match
			if ns == denied {
				return true
			}
		}
	}
	return false
}

// OwnerResolver checks if an owner identified by namespace/name/uid still
// exists. Returns true if the owner is still valid, false if it should be
// considered orphaned. The resolver is a function type to keep the library
// independent of specific CR types — callers provide the resolution logic.
type OwnerResolver func(ctx context.Context, namespace, name string, uid types.UID) (exists bool, err error)

// GCResult contains the results of a garbage collection run.
type GCResult struct {
	// ResourcesScanned is the number of managed resources examined.
	ResourcesScanned int
	// EntriesRemoved is the number of stale owner entries removed.
	EntriesRemoved int
	// ResourcesDeleted is the number of resources deleted (no owners remaining).
	ResourcesDeleted int
}

// gcSplitAnnotationEntries splits a comma-separated annotation value into
// individual non-empty, trimmed entries. Used by GC methods.
func gcSplitAnnotationEntries(value string) []string {
	raw := strings.Split(value, ",")
	entries := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// gcParseOwnerEntry parses a single annotation entry in "namespace/name/uid"
// format. Returns nil if the entry is malformed (not exactly 3 parts).
func gcParseOwnerEntry(entry string) []string {
	parts := strings.SplitN(entry, "/", 3)
	if len(parts) != 3 {
		return nil
	}
	return parts
}

// gcJoinAnnotationEntries joins annotation entries back into a comma-separated
// string.
func gcJoinAnnotationEntries(entries []string) string {
	return strings.Join(entries, ",")
}

// gcAnnotationOwnersShared is the shared GC logic for both RBACScoper and
// ClusterRBACScoper. It parses annotation owner entries, resolves each via
// the resolver, removes stale or malformed entries, and deletes the resource
// if no owners remain. When checkOwnerRefs is true (namespace-scoped), both
// OwnerReferences and annotation entries must be empty before deletion.
// When false (cluster-scoped), only annotation entries are checked.
func gcAnnotationOwnersShared(
	ctx context.Context,
	cl client.Client,
	obj client.Object,
	annotationKey string,
	resolver OwnerResolver,
	kind string,
	checkOwnerRefs bool,
) (removed int, deleted bool, err error) {
	log := ctrl.LoggerFrom(ctx)
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return 0, false, nil
	}
	existing := annotations[annotationKey]
	if existing == "" {
		return 0, false, nil
	}

	entries := gcSplitAnnotationEntries(existing)
	var validEntries []string
	for _, entry := range entries {
		parts := gcParseOwnerEntry(entry)
		if parts == nil {
			log.Info("removing malformed annotation entry", "entry", entry, "kind", kind, "name", obj.GetName(), "namespace", obj.GetNamespace())
			removed++
			continue
		}
		ns, name, uid := parts[0], parts[1], types.UID(parts[2])
		exists, resolveErr := resolver(ctx, ns, name, uid)
		if resolveErr != nil {
			// Return 0 for removed: no changes have been persisted yet,
			// so reporting partial removals would be misleading.
			return 0, false, fmt.Errorf("resolving owner %s: %w", entry, resolveErr)
		}
		if !exists {
			log.Info("removing orphaned annotation entry", "entry", entry, "kind", kind, "name", obj.GetName(), "namespace", obj.GetNamespace())
			removed++
			continue
		}
		validEntries = append(validEntries, entry)
	}

	if removed == 0 {
		return 0, false, nil
	}

	// Update the annotation
	if len(validEntries) == 0 {
		delete(annotations, annotationKey)
	} else {
		annotations[annotationKey] = gcJoinAnnotationEntries(validEntries)
	}
	obj.SetAnnotations(annotations)

	// Determine if any owners remain
	hasAnnotationOwners := len(validEntries) > 0
	hasOwnerRefs := checkOwnerRefs && len(obj.GetOwnerReferences()) > 0

	if !hasOwnerRefs && !hasAnnotationOwners {
		if delErr := cl.Delete(ctx, obj); delErr != nil && !apierrors.IsNotFound(delErr) {
			return removed, false, fmt.Errorf("deleting %s %s/%s: %w", kind, obj.GetNamespace(), obj.GetName(), delErr)
		}
		log.Info("deleted "+kind+" during GC (no owners remain)", "name", obj.GetName(), "namespace", obj.GetNamespace())
		return removed, true, nil
	}

	if err := cl.Update(ctx, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return removed, false, nil
		}
		return removed, false, fmt.Errorf("updating %s %s/%s during GC: %w", kind, obj.GetNamespace(), obj.GetName(), err)
	}
	log.Info("removed stale annotation entries from "+kind, "name", obj.GetName(), "namespace", obj.GetNamespace(), "removed", removed)
	return removed, false, nil
}
