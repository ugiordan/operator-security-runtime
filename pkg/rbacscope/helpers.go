package rbacscope

import (
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ownerAnnotationKey is the annotation used to track cross-namespace owners.
	// Unlike OwnerReferences, annotations can reference objects in other namespaces.
	ownerAnnotationKey = "opendatahub.io/scoped-access-owners"

	// maxAnnotationOwners limits the number of owner entries stored in the
	// annotation to prevent unbounded growth.
	maxAnnotationOwners = 100
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

	// Check if owner is already present
	entries := strings.Split(existing, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == key {
			return nil // already present
		}
	}

	if len(entries) >= maxAnnotationOwners {
		return fmt.Errorf("maximum owner count (%d) exceeded for annotation %s", maxAnnotationOwners, t.annotationKey)
	}

	annotations[t.annotationKey] = existing + "," + key
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
	return existing != ""
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
