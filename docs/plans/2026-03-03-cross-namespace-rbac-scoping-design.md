# Cross-Namespace and Cluster-Scoped RBAC Scoping Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend `pkg/rbacscope` to support cross-namespace and cluster-scoped
dynamic RBAC, covering all RHOAI access patterns that the current same-namespace
`RBACScoper` cannot handle.

**Architecture:** Three scoper types share a common constructor pattern and
internal helpers. `RBACScoper` handles same-namespace and cross-namespace
grants via Roles/RoleBindings. `ClusterRBACScoper` handles cluster-scoped
grants via ClusterRoles/ClusterRoleBindings using the Kubernetes
escalate/bind pattern. Both use annotation-based ownership for cross-namespace
resources (where OwnerReferences are not supported) and label-selected listing
for tracking managed resources.

**Tech Stack:** Go, controller-runtime, `rbacv1`, `controllerutil`,
Server-Side Apply (SSA)

---

## 1. Problem Statement

RHOAI operators access resources across five distinct patterns. Today the
library covers only one (Pattern 5: same-namespace). The remaining patterns
require cross-namespace Roles or cluster-scoped ClusterRoles.

### Access Patterns in RHOAI

| # | Pattern | Example | Current Coverage |
|---|---------|---------|-----------------|
| 5 | Same-namespace resource access | DSPA reads secrets in its own namespace | **Covered** by `RBACScoper.EnsureAccess` |
| 1 | Fixed infrastructure namespace | KNative reads secrets in `openshift-ingress` | Not covered |
| 2 | User-configurable remote namespace | DSPA reads secrets from `cr.Spec.SecretNS` | Not covered |
| 3 | Operator namespace access | Controller reads secrets in `POD_NAMESPACE` | Not covered |
| 4a | CRD existence check | Feast checks if MLFlow CRD is installed | Not covered (docs only) |
| 4b | Cluster resource collection | Kueue lists Nodes, Namespaces | Not covered (docs only) |
| 4c | CR instance discovery | Controller lists CRs across all namespaces | Not covered |

### What This Design Adds

| Pattern | Mechanism | Method |
|---------|-----------|--------|
| 1, 2, 3 | Cross-namespace Roles/RoleBindings | `RBACScoper.EnsureAccessInNamespace(ctx, owner, targetNS)` |
| 4c | Cluster-scoped ClusterRoles/ClusterRoleBindings | `ClusterRBACScoper.EnsureClusterAccess(ctx, owner)` |
| 4a, 4b | Documented guidance only | Static ClusterRole (irreducible minimum) |

---

## 2. API Design

### 2.1 Constructor Pattern (Functional Options)

All struct fields are **unexported**. Construction goes through validated
constructors.

```go
// pkg/rbacscope/option.go

// Option configures an RBACScoper or ClusterRBACScoper.
// The unexported apply method prevents external implementations.
type Option interface {
    apply(s *scopeConfig)
}

type optionFunc func(s *scopeConfig)

func (f optionFunc) apply(s *scopeConfig) { f(s) }
```

**Required parameters** are constructor arguments, not options:

```go
// OperatorIdentity groups the required identity fields.
type OperatorIdentity struct {
    Name             string // Operator name, used in Role/RoleBinding naming
    ServiceAccount   string // Operator's ServiceAccount name
    Namespace        string // Operator's ServiceAccount namespace
}

// AllowedRules defines the security ceiling — the maximum set of PolicyRules
// that any scoped Role or ClusterRole may contain. Rules requested at
// EnsureAccess time are validated against this ceiling.
type AllowedRules struct {
    rules []rbacv1.PolicyRule
}

// NewAllowedRules creates a validated AllowedRules.
// Returns error if rules is empty.
func NewAllowedRules(rules ...rbacv1.PolicyRule) (AllowedRules, error)

// AllowAllRules returns an AllowedRules that permits any PolicyRule.
// Use only when the operator's static RBAC already constrains access
// and the library ceiling adds no value.
func AllowAllRules() AllowedRules
```

**Options:**

```go
// WithDeniedNamespaces prevents the scoper from creating Roles in
// specified namespaces. Defaults to kube-system, kube-public,
// kube-node-lease, openshift-*, default.
func WithDeniedNamespaces(namespaces ...string) Option

// WithAggregationLabelCheck causes EnsureAccess to verify that the
// operator's ClusterRole does NOT carry aggregation labels
// (e.g., aggregate-to-edit). If it does, EnsureAccess returns an error
// to prevent unintended privilege escalation through aggregation.
func WithAggregationLabelCheck(enabled bool) Option
```

### 2.2 RBACScoper (Same-Namespace + Cross-Namespace)

```go
// NewRBACScoper creates a validated RBACScoper.
func NewRBACScoper(
    cl client.Client,
    scheme *runtime.Scheme,
    identity OperatorIdentity,
    allowed AllowedRules,
    opts ...Option,
) (*RBACScoper, error)

// EnsureAccess creates/updates a Role and RoleBinding in the owner's
// namespace. Uses OwnerReferences for lifecycle tracking.
// This is the existing method — no API change.
func (s *RBACScoper) EnsureAccess(ctx context.Context, owner client.Object) error

// EnsureAccessInNamespace creates/updates a Role and RoleBinding in
// targetNS for the owner. Uses annotation-based ownership because
// cross-namespace OwnerReferences are not supported by Kubernetes.
func (s *RBACScoper) EnsureAccessInNamespace(
    ctx context.Context,
    owner client.Object,
    targetNS string,
) error

// CleanupAccess removes same-namespace RBAC (existing behavior).
func (s *RBACScoper) CleanupAccess(ctx context.Context, owner client.Object) error

// CleanupAllAccess removes the owner's references from all managed
// Roles and RoleBindings across namespaces. Uses label-selected listing
// to find managed resources.
func (s *RBACScoper) CleanupAllAccess(ctx context.Context, owner client.Object) error
```

### 2.3 ClusterRBACScoper

```go
// NewClusterRBACScoper creates a validated ClusterRBACScoper.
func NewClusterRBACScoper(
    cl client.Client,
    scheme *runtime.Scheme,
    identity OperatorIdentity,
    allowed AllowedRules,
    opts ...Option,
) (*ClusterRBACScoper, error)

// EnsureClusterAccess creates/updates a ClusterRole and
// ClusterRoleBinding for the operator's ServiceAccount.
// Uses annotation-based ownership (ClusterRoles are cluster-scoped,
// OwnerReferences require same-namespace).
func (s *ClusterRBACScoper) EnsureClusterAccess(
    ctx context.Context,
    owner client.Object,
) error

// CleanupClusterAccess removes the owner's annotation from the
// ClusterRole and ClusterRoleBinding. Deletes if no owners remain.
func (s *ClusterRBACScoper) CleanupClusterAccess(
    ctx context.Context,
    owner client.Object,
) error
```

### 2.4 Backward Compatibility

The current public struct fields (`Client`, `Scheme`, `OperatorName`, etc.)
become unexported. This is a **breaking change**. Existing consumers must
migrate to `NewRBACScoper(...)`. Since the library is pre-1.0 and has only
the example operator as a consumer, this is acceptable.

A migration example:

```go
// Before:
scoper := &rbacscope.RBACScoper{
    Client:              mgr.GetClient(),
    Scheme:              mgr.GetScheme(),
    OperatorName:        "my-operator",
    OperatorSAName:      "my-operator-sa",
    OperatorSANamespace: "my-operator-system",
    Rules: []rbacv1.PolicyRule{{
        APIGroups: []string{""},
        Resources: []string{"secrets"},
        Verbs:     []string{"get", "list", "watch"},
    }},
}

// After:
allowed, err := rbacscope.NewAllowedRules(rbacv1.PolicyRule{
    APIGroups: []string{""},
    Resources: []string{"secrets"},
    Verbs:     []string{"get", "list", "watch"},
})
if err != nil { ... }

scoper, err := rbacscope.NewRBACScoper(
    mgr.GetClient(),
    mgr.GetScheme(),
    rbacscope.OperatorIdentity{
        Name:           "my-operator",
        ServiceAccount: "my-operator-sa",
        Namespace:      "my-operator-system",
    },
    allowed,
)
if err != nil { ... }
```

---

## 3. Ownership and Cleanup

### 3.1 Same-Namespace (Existing Behavior)

Uses Kubernetes **OwnerReferences**. Multiple CRs in the same namespace each
add themselves as owners. Cleanup removes one OwnerReference; deletion occurs
only when no owners remain. This is unchanged.

### 3.2 Cross-Namespace (New)

Kubernetes does not support cross-namespace OwnerReferences. The library uses
**annotation-based ownership** with Server-Side Apply (SSA).

**Annotation format:**

```
opendatahub.io/scoped-access-owners: "<ns1>/<name1>/<uid1>,<ns2>/<name2>/<uid2>"
```

**SSA with dedicated FieldOwner** (`operator-security-runtime`) ensures that:
- Concurrent updates from multiple reconcilers do not overwrite each other
- The annotation is read inside the mutate function to avoid TOCTOU races
- Only the library's field manager owns the annotation

**Label-based discovery:**

Managed resources carry labels for efficient listing:

```yaml
labels:
  app.kubernetes.io/managed-by: "<operator-name>"
  app.kubernetes.io/component: "rbac-scoper"
```

`CleanupAllAccess` lists all Roles/RoleBindings matching these labels, removes
the owner's entry from each annotation, and deletes resources with no owners.

### 3.3 Cluster-Scoped (New)

Same annotation-based pattern as cross-namespace. ClusterRoles and
ClusterRoleBindings cannot have OwnerReferences pointing to namespaced
resources, so annotations track ownership identically.

### 3.4 Orphan Garbage Collection

A periodic reconciler action scans for managed RBAC resources whose owner
annotations reference CRs that no longer exist. This handles:
- Controller crashes during cleanup
- Finalizer bypass (force-deleted CRs)
- Manual annotation corruption

The GC runs as part of the normal reconciliation loop, not as a separate
controller. It lists resources by label, resolves each owner annotation entry,
and removes stale entries.

---

## 4. RBAC Prerequisites

### 4.1 Namespace-Scoped (RBACScoper)

The operator's static ClusterRole needs:

```yaml
# Create new Roles and RoleBindings in any namespace
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings"]
  verbs: ["create"]

# Manage specific Roles by resourceNames (escalate/bind scoped)
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles"]
  resourceNames: ["<operator>-scoped-access"]
  verbs: ["escalate", "bind", "get", "update", "patch", "delete"]

# Manage specific RoleBindings by resourceNames
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings"]
  resourceNames: ["<operator>-scoped-access-binding"]
  verbs: ["get", "update", "patch", "delete"]
```

The `escalate` verb is scoped to a specific `resourceNames` entry. This means
the operator can only escalate the Roles it creates (named
`<operator>-scoped-access`), not arbitrary Roles. The `bind` verb similarly
restricts which Roles can be referenced in RoleBindings.

### 4.2 Cluster-Scoped (ClusterRBACScoper)

```yaml
# Create new ClusterRoles and ClusterRoleBindings
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]
  verbs: ["create"]

# Manage specific ClusterRoles by resourceNames
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  resourceNames: ["<operator>-cluster-scoped-access"]
  verbs: ["escalate", "bind", "get", "update", "patch", "delete"]

# Manage specific ClusterRoleBindings by resourceNames
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  resourceNames: ["<operator>-cluster-scoped-access-binding"]
  verbs: ["get", "update", "patch", "delete"]
```

### 4.3 Why escalate + resourceNames

The Kubernetes RBAC escalation model prevents a ServiceAccount from creating a
Role that grants permissions it does not itself hold — unless the SA has the
`escalate` verb. By scoping `escalate` to a specific `resourceNames`, we:

1. Allow the library to create Roles granting arbitrary permissions (within
   the `AllowedRules` ceiling)
2. Prevent the operator from escalating arbitrary Roles it did not create
3. Provide auditable, minimal-privilege RBAC for the operator itself

The `bind` verb allows the operator to create RoleBindings referencing the
managed Role, even if the operator does not hold all permissions in that Role.

---

## 5. Security Model

### 5.1 AllowedRules Ceiling

`AllowedRules` is a **required** constructor parameter. It defines the maximum
set of permissions that any dynamically created Role or ClusterRole may contain.
At `EnsureAccess` / `EnsureClusterAccess` time, the requested `Rules` are
validated against this ceiling. If a rule exceeds the ceiling, the operation
returns an error.

This prevents a compromised reconciler from using the library to escalate
beyond its intended scope.

`AllowAllRules()` is an explicit escape hatch for operators whose static RBAC
already constrains access and where the library ceiling adds no value. Its use
is logged.

### 5.2 DeniedNamespaces

The scoper refuses to create Roles in sensitive namespaces. Defaults:

- `kube-system`, `kube-public`, `kube-node-lease`
- `openshift-*` (prefix match)
- `default`

Operators can override with `WithDeniedNamespaces(...)`.

### 5.3 Aggregation Label Check

If `WithAggregationLabelCheck(true)` is set, the scoper verifies that the
operator's ClusterRole does not carry aggregation labels (e.g.,
`rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`). A ClusterRole
with aggregation labels would have its rules merged into broader roles like
`edit` or `admin`, defeating the purpose of scoped access.

### 5.4 Annotation Integrity

Cross-namespace annotations are managed via SSA with a dedicated
`FieldOwner`. This prevents other controllers from accidentally overwriting
the ownership annotation. The annotation is read inside the mutate function
of `controllerutil.CreateOrUpdate` to avoid TOCTOU races.

---

## 6. Code Structure and Patterns

### 6.1 File Layout

```
pkg/rbacscope/
  doc.go                    # Package documentation
  option.go                 # Option interface, optionFunc, With* constructors
  identity.go               # OperatorIdentity, AllowedRules types
  rbac_scoper.go            # RBACScoper (same-NS + cross-NS)
  cluster_rbac_scoper.go    # ClusterRBACScoper
  helpers.go                # Shared unexported helpers
  rbac_scoper_test.go       # Tests for RBACScoper
  cluster_rbac_scoper_test.go # Tests for ClusterRBACScoper
```

### 6.2 Line of Sight Refactoring

Existing code in `rbac_scoper.go` has two nesting issues that will be
addressed:

**`CleanupAccess` (60 lines → ~18 lines):**

Extract `cleanupOwnedResource(ctx, obj, key, owner, kind)` to deduplicate
the Role/RoleBinding cleanup logic.

```go
func (s *RBACScoper) CleanupAccess(ctx context.Context, owner client.Object) error {
    if err := s.validate(); err != nil {
        return fmt.Errorf("invalid RBACScoper configuration: %w", err)
    }
    ns := owner.GetNamespace()
    if ns == "" {
        return fmt.Errorf("owner must be namespace-scoped ...")
    }

    if err := s.cleanupOwnedResource(ctx,
        &rbacv1.Role{},
        types.NamespacedName{Name: s.roleName(), Namespace: ns},
        owner, "Role"); err != nil {
        return err
    }
    return s.cleanupOwnedResource(ctx,
        &rbacv1.RoleBinding{},
        types.NamespacedName{Name: s.roleBindingName(), Namespace: ns},
        owner, "RoleBinding")
}
```

**`ensureRoleBinding` (4-level nesting → 2-level):**

Extract `recreateRoleBinding(ctx, ns, mutateFn)` and
`roleBindingMutateFn(rb, owner)` to flatten the error handling path.

### 6.3 Shared Helpers

Cross-namespace and cluster-scoped cleanup share the same annotation-based
ownership logic. An unexported helper struct `annotationOwnerTracker`
provides:

```go
type annotationOwnerTracker struct {
    annotationKey string
    fieldOwner    string
}

func (t *annotationOwnerTracker) addOwner(obj client.Object, owner client.Object)
func (t *annotationOwnerTracker) removeOwner(obj client.Object, owner client.Object)
func (t *annotationOwnerTracker) hasOwners(obj client.Object) bool
func (t *annotationOwnerTracker) ownerKey(owner client.Object) string
```

Both `RBACScoper` (cross-NS path) and `ClusterRBACScoper` embed this tracker.

### 6.4 Functional Options Scope

The functional options pattern applies **only to `rbacscope`**. The other
packages (`saprotection`, `impersonationguard`, `rbacaudit`) have simple
configurations that do not benefit from options.

---

## 7. Role Naming

### Same-Namespace

```
<operator-name>-scoped-access           (Role)
<operator-name>-scoped-access-binding   (RoleBinding)
```

Unchanged from current behavior.

### Cross-Namespace

Same naming scheme. The Role is created in the target namespace, not the
owner's namespace. Labels and annotations distinguish it.

### Cluster-Scoped

```
<operator-name>-cluster-scoped-access           (ClusterRole)
<operator-name>-cluster-scoped-access-binding   (ClusterRoleBinding)
```

---

## 8. Patterns Not Covered by the Library

### 4a: CRD Existence Check

Checking whether a CRD is installed requires `get`/`list` on
`customresourcedefinitions` (cluster-scoped). This is a chicken-and-egg
problem: the library cannot create RBAC to check for something when it does
not yet know if that something exists.

**Recommendation:** Use a static ClusterRole entry:

```yaml
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  resourceNames: ["featurestores.feast.dev"]
  verbs: ["get"]
```

Scoped to `resourceNames` for minimal privilege.

### 4b: Cluster Resource Collection

Listing Nodes, Namespaces, or other cluster-scoped resources requires a
static ClusterRole. These are irreducible minimums that cannot be dynamically
scoped.

**Recommendation:** Static ClusterRole with read-only verbs:

```yaml
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
```

---

## 9. Integration Examples

### Cross-Namespace: User-Configurable Secret Namespace

```go
func (r *DSPAReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    dspa := &v1alpha1.DSPA{}
    if err := r.Get(ctx, req.NamespacedName, dspa); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Same-namespace scoped access (secrets in DSPA namespace)
    if err := r.RBACScoper.EnsureAccess(ctx, dspa); err != nil {
        return ctrl.Result{}, err
    }

    // Cross-namespace access if user configured a remote secret namespace
    if dspa.Spec.SecretNamespace != "" {
        if err := r.RBACScoper.EnsureAccessInNamespace(
            ctx, dspa, dspa.Spec.SecretNamespace,
        ); err != nil {
            return ctrl.Result{}, err
        }
    }

    // ... business logic ...
    return ctrl.Result{}, nil
}
```

### Cluster-Scoped: CR Instance Discovery

```go
func (r *FeastReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    fs := &feastv1.FeatureStore{}
    if err := r.Get(ctx, req.NamespacedName, fs); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Cluster-wide access to list FeatureStore CRs across namespaces
    if err := r.ClusterRBACScoper.EnsureClusterAccess(ctx, fs); err != nil {
        return ctrl.Result{}, err
    }

    // ... list FeatureStores across namespaces ...
    return ctrl.Result{}, nil
}
```

### Cleanup in Finalizer

```go
func (r *DSPAReconciler) handleDeletion(ctx context.Context, dspa *v1alpha1.DSPA) (ctrl.Result, error) {
    // CleanupAllAccess removes this owner from all managed Roles/RoleBindings
    // across all namespaces (both same-NS and cross-NS)
    if err := r.RBACScoper.CleanupAllAccess(ctx, dspa); err != nil {
        return ctrl.Result{}, err
    }

    controllerutil.RemoveFinalizer(dspa, finalizerName)
    return ctrl.Result{}, r.Update(ctx, dspa)
}
```

---

## 10. Decisions from Architect Review

The following decisions were reached through a 5-round architect review with
Security, API Design, and Implementation architects.

### Consensus Items

| Decision | Rationale |
|----------|-----------|
| Separate methods: `EnsureAccess` + `EnsureAccessInNamespace` | Same-namespace callers should not be burdened with a `targetNS` parameter they don't need |
| `AllowedRules` as required constructor param | Security ceiling must be explicit; no default "allow everything" |
| `AllowAllRules()` explicit escape hatch | Operators that need flexibility get it, but must opt in explicitly |
| Annotation-based ownership for cross-NS | Kubernetes does not support cross-namespace OwnerReferences |
| SSA + dedicated FieldOwner for annotations | Prevents concurrent annotation corruption |
| Label-selected listing for managed resources | Consistent with existing GC patterns, avoids CR annotation mutation |
| DeniedNamespaces with sensible defaults | Prevents accidental RBAC grants in system namespaces |
| Aggregation label check | Prevents operator ClusterRoles from leaking permissions via aggregation |
| Single finalizer, auto-registered by library | Reduces integration complexity for consumers |
| Annotation read inside mutate function | Prevents TOCTOU races between annotation read and write |
| Orphan GC as reconciler action | Handles crash recovery and force-deleted CRs |

### Resolved Disagreements

| Topic | Resolution |
|-------|-----------|
| Separate vs. single finalizer | Single finalizer — library registers cleanup as part of existing finalizer chain |
| SSA vs. webhook for annotation integrity | SSA with FieldOwner — no webhook; less infrastructure, sufficient protection |
| AllowedRules required vs. optional | Required constructor param with `AllowAllRules()` escape |
| Label scanning vs. CR annotation for namespace tracking | Label scanning — avoids contention on CR annotations, consistent with GC pattern |

---

## 11. Implementation Plan

### Phase 1: Refactor Existing Code

1. Create `option.go` with `Option` interface, `optionFunc`, `WithDeniedNamespaces`, `WithAggregationLabelCheck`
2. Create `identity.go` with `OperatorIdentity`, `AllowedRules`, `NewAllowedRules`, `AllowAllRules`
3. Add `NewRBACScoper` constructor; make struct fields unexported
4. Extract `cleanupOwnedResource` helper from `CleanupAccess`
5. Extract `recreateRoleBinding` from `ensureRoleBinding`
6. Update all tests to use `NewRBACScoper`
7. Update example operator

### Phase 2: Cross-Namespace Support

1. Add `annotationOwnerTracker` to `helpers.go`
2. Implement `EnsureAccessInNamespace` with annotation-based ownership
3. Implement `CleanupAllAccess` with label-selected listing
4. Add orphan GC logic
5. Add tests for cross-namespace scenarios
6. Update documentation

### Phase 3: Cluster-Scoped Support

1. Create `cluster_rbac_scoper.go` with `NewClusterRBACScoper`
2. Implement `EnsureClusterAccess` with escalate/bind pattern
3. Implement `CleanupClusterAccess`
4. Add tests for cluster-scoped scenarios
5. Update documentation with RBAC prerequisites

### Phase 4: Documentation Updates

Every documentation file must reflect the new constructor API, cross-namespace
support, cluster-scoped support, and security model. Changes are listed
file-by-file with specific sections to update or add.

#### 4.1 `README.md`

**Update existing sections:**

- **Quick Start > Dynamic RBAC Scoping**: Replace struct initialization with
  `NewRBACScoper(...)` constructor. Show `OperatorIdentity` and
  `NewAllowedRules(...)` usage.

  ```go
  // Before (current):
  scoper := &rbacscope.RBACScoper{
      Client: mgr.GetClient(),
      ...
      Rules: []rbacv1.PolicyRule{{...}},
  }

  // After:
  allowed, _ := rbacscope.NewAllowedRules(rbacv1.PolicyRule{...})
  scoper, _ := rbacscope.NewRBACScoper(
      mgr.GetClient(),
      mgr.GetScheme(),
      rbacscope.OperatorIdentity{
          Name:           "my-operator",
          ServiceAccount: "my-operator-sa",
          Namespace:      "my-operator-system",
      },
      allowed,
  )
  ```

- **Packages > `pkg/rbacscope`**: Add mention of `EnsureAccessInNamespace`
  and `ClusterRBACScoper`. Update the description from "namespace where
  operator CRs exist" to include cross-namespace grants.

- **How It Works table**: Add column for Dynamic RBAC Scoping to mention
  cross-NS and cluster-scoped variants.

- **Defense in Depth section**: Update to mention that RBAC scoping now covers
  cross-namespace access patterns, not just same-namespace.

**Add new sections:**

- **Quick Start > Cross-Namespace RBAC Scoping**: Show
  `EnsureAccessInNamespace` usage with a user-configurable namespace example.

- **Quick Start > Cluster-Scoped RBAC Scoping**: Show
  `NewClusterRBACScoper` and `EnsureClusterAccess` usage.

- **Mermaid diagram**: Add cross-namespace lifecycle flowchart showing:
  CR created → `EnsureAccessInNamespace` → Role in remote NS with annotation
  ownership → CR deleted → `CleanupAllAccess` → annotation removed → Role
  deleted if no owners.

#### 4.2 `docs/TECHNICAL_DESIGN.md`

**Update existing sections:**

- **Section 4 (Mechanism 2: Dynamic RBAC Scoping)**: Rename to
  "Mechanism 2: Dynamic RBAC Scoping (`pkg/rbacscope`)" (already named this).
  Update the "Problem" subsection to mention cross-namespace access patterns.

- **CR Lifecycle Flow**: Update the Mermaid diagram to show both same-NS
  (OwnerReference) and cross-NS (annotation) paths as separate branches.

- **Multi-CR Ownership**: Add subsection on annotation-based ownership for
  cross-namespace resources. Explain format:
  `opendatahub.io/scoped-access-owners: "<ns>/<name>/<uid>,..."`.

- **Escalate Verb**: Expand to cover the `escalate` + `bind` +
  `resourceNames` pattern. Show RBAC prerequisite YAML for both
  namespace-scoped and cluster-scoped.

- **Coverage table**: Add columns for cross-NS and cluster-scoped patterns.
  Update each operator row with which patterns they use.

- **Section 6 (Key Architectural Tradeoffs)**: Add tradeoff entries for:
  - Annotation-based ownership vs. OwnerReferences
  - SSA with FieldOwner vs. webhook for annotation integrity
  - AllowedRules ceiling vs. open escalation
  - DeniedNamespaces defaults

**Add new sections:**

- **Section 4.X: Cross-Namespace Scoping**: Dedicated subsection covering
  annotation ownership, SSA field management, label-based discovery,
  DeniedNamespaces, and the cleanup flow.

- **Section 4.Y: Cluster-Scoped Dynamic RBAC**: Dedicated subsection covering
  ClusterRole/ClusterRoleBinding lifecycle, escalate/bind pattern,
  annotation-based ownership for cluster resources, and the orphan GC
  reconciler.

- **Section 4.Z: Security Model**: Dedicated subsection covering
  AllowedRules ceiling, DeniedNamespaces, aggregation label check, and
  annotation integrity via SSA.

- **Mermaid diagrams**:
  - Cross-namespace lifecycle (CR → Role in remote NS → annotation → cleanup)
  - Cluster-scoped lifecycle (CR → ClusterRole → annotation → cleanup)
  - AllowedRules validation flow (requested rules → ceiling check → allow/deny)
  - Orphan GC flow (label scan → resolve annotations → stale entry → remove)

#### 4.3 `docs/INTEGRATION_GUIDE.md`

**Update existing sections:**

- **Section 3.1 (Initialize Scoper)**: Replace struct initialization with
  `NewRBACScoper(...)` constructor. Show `OperatorIdentity`,
  `NewAllowedRules`, and options (`WithDeniedNamespaces`).

- **Section 3.2 (Update Reconciler)**: Update reconciler struct field type
  annotation (pointer to `*rbacscope.RBACScoper` is unchanged, but
  construction changes).

- **Section 3.3 (Add Finalizer for Cleanup)**: Update to use
  `CleanupAllAccess` instead of `CleanupAccess` for operators that use
  cross-namespace access. Add conditional logic showing when to use each.

- **Section 3.5 (Add RBAC Markers)**: Update kubebuilder markers to include
  `escalate`, `bind` scoped to `resourceNames`. Add cluster-scoped markers
  for `ClusterRBACScoper` users.

- **Section 3.6 (Remove Scoped Resources from ClusterRole)**: Update to
  mention that cross-namespace access also removes the need for cluster-wide
  grants to remote namespaces.

- **Section 4 (Configuration) > Custom Rules**: Already shows multi-resource
  rules. Add note about `AllowedRules` ceiling and how it constrains what
  rules can be passed to `EnsureAccess`.

- **Section 4 > Cross-Controller CRD Access**: Update the "Limitation" note
  to mention `EnsureAccessInNamespace` as the solution for CRs in different
  namespaces.

- **Section 5 (Migration)**: Add migration step for existing consumers moving
  from struct initialization to `NewRBACScoper(...)` constructor.

**Add new sections:**

- **Section 3.X: Add Cross-Namespace RBAC Scoping**: Full walkthrough:
  1. Initialize scoper with `NewRBACScoper(...)` (same instance covers both)
  2. Call `EnsureAccessInNamespace(ctx, cr, targetNS)` in reconciler
  3. Call `CleanupAllAccess(ctx, cr)` in finalizer
  4. Watch managed RBAC resources across namespaces
  5. RBAC marker additions

  Include examples for each sub-pattern:
  - Fixed infrastructure NS (`"openshift-ingress"`)
  - User-configurable NS (`cr.Spec.SecretNamespace`)
  - Operator NS (`os.Getenv("POD_NAMESPACE")`)

- **Section 3.Y: Add Cluster-Scoped RBAC Scoping**: Full walkthrough:
  1. Initialize `NewClusterRBACScoper(...)`
  2. Call `EnsureClusterAccess(ctx, cr)` in reconciler
  3. Call `CleanupClusterAccess(ctx, cr)` in finalizer
  4. RBAC prerequisite YAML (escalate/bind on clusterroles)
  5. Combined usage: cluster discovery + per-namespace scoped access

- **Section 3.Z: Security Configuration**: Explain:
  - `AllowedRules` and `NewAllowedRules(...)` vs `AllowAllRules()`
  - `WithDeniedNamespaces(...)` and defaults
  - `WithAggregationLabelCheck(true)` and when to use it

- **Section 5.X: Migration from Struct Initialization to Constructor**:
  Step-by-step migration guide for existing library consumers:
  1. Replace `&rbacscope.RBACScoper{...}` with `NewRBACScoper(...)`
  2. Create `AllowedRules` from existing `Rules` field
  3. Create `OperatorIdentity` from existing fields
  4. Update error handling (constructor now returns error)
  5. Update tests

- **Section 8.X: Troubleshooting > Cross-Namespace**: Add entries for:
  - Annotation corruption recovery
  - Orphan RBAC resources after force-deletion
  - DeniedNamespace rejection errors

- **Section 8.Y: Troubleshooting > Cluster-Scoped**: Add entries for:
  - escalate/bind permission errors
  - ClusterRole naming conflicts

#### 4.4 `pkg/rbacscope/doc.go`

Replace the package documentation to reflect the new API:

```go
// Package rbacscope provides dynamic RBAC scoping for Kubernetes operators.
//
// RBACScoper creates and manages namespace-scoped Roles and RoleBindings so
// that an operator ServiceAccount can access resources only in namespaces
// where a Custom Resource exists or where the CR specifies a target namespace.
//
// ClusterRBACScoper creates and manages cluster-scoped ClusterRoles and
// ClusterRoleBindings for operators that need cluster-wide resource access
// tied to CR lifecycle (e.g., listing CRs across all namespaces).
//
// Both types are constructed via NewRBACScoper and NewClusterRBACScoper,
// which validate required parameters and accept functional options.
//
// Usage:
//
//     allowed, err := rbacscope.NewAllowedRules(rbacv1.PolicyRule{
//         APIGroups: []string{""},
//         Resources: []string{"secrets"},
//         Verbs:     []string{"get", "list", "watch"},
//     })
//
//     scoper, err := rbacscope.NewRBACScoper(
//         mgr.GetClient(),
//         mgr.GetScheme(),
//         rbacscope.OperatorIdentity{
//             Name:           "my-operator",
//             ServiceAccount: "my-operator-controller-manager",
//             Namespace:      "my-operator-system",
//         },
//         allowed,
//     )
//
//     // Same-namespace:
//     scoper.EnsureAccess(ctx, cr)
//
//     // Cross-namespace:
//     scoper.EnsureAccessInNamespace(ctx, cr, cr.Spec.SecretNamespace)
//
//     // Cleanup (finalizer):
//     scoper.CleanupAllAccess(ctx, cr)
```

### Phase 5: Example Operator and Test Updates

All example source code and tests must be updated to use the new constructor
API and demonstrate cross-namespace patterns.

#### 5.1 `examples/operator/cmd/main.go`

**Changes:**

- Replace struct initialization `&rbacscope.RBACScoper{...}` (lines 140-151)
  with `NewRBACScoper(...)` constructor
- Add `AllowedRules` creation with `NewAllowedRules(...)`
- Add `OperatorIdentity` struct initialization
- Add error handling for constructor (currently none)
- Add optional cross-NS demo: initialize a second scoper or reuse the same
  one with `EnsureAccessInNamespace` in the reconciler

```go
// Before:
rbacScoper := &rbacscope.RBACScoper{
    Client:              mgr.GetClient(),
    Scheme:              mgr.GetScheme(),
    OperatorName:        operatorName,
    OperatorSAName:      operatorSA,
    OperatorSANamespace: operatorNS,
    Rules: []rbacv1.PolicyRule{{...}},
}

// After:
allowed, err := rbacscope.NewAllowedRules(rbacv1.PolicyRule{
    APIGroups: []string{""},
    Resources: []string{"secrets"},
    Verbs:     []string{"get", "list", "watch"},
})
if err != nil {
    setupLog.Error(err, "invalid allowed rules")
    os.Exit(1)
}

rbacScoper, err := rbacscope.NewRBACScoper(
    mgr.GetClient(),
    mgr.GetScheme(),
    rbacscope.OperatorIdentity{
        Name:           operatorName,
        ServiceAccount: operatorSA,
        Namespace:      operatorNS,
    },
    allowed,
)
if err != nil {
    setupLog.Error(err, "unable to create RBAC scoper")
    os.Exit(1)
}
```

#### 5.2 `examples/operator/internal/controller/exampleresource_controller.go`

**Changes:**

- Add `EnsureAccessInNamespace` call when the CR specifies a remote namespace
  (add a `Spec.SecretNamespace` field to the example CRD, or use a hardcoded
  demo namespace)
- Update finalizer cleanup from `CleanupAccess` to `CleanupAllAccess` to
  cover cross-NS resources
- Update RBAC markers to include `escalate` and `bind` scoped to
  `resourceNames`
- Keep the existing `EnsureAccess` call for same-namespace access

```go
// Updated reconcile flow:
// Step 1: Same-namespace scoped access
if err := r.RBACScoper.EnsureAccess(ctx, cr); err != nil {
    return ctrl.Result{}, fmt.Errorf("ensuring same-NS access: %w", err)
}

// Step 2: Cross-namespace access (if configured)
if cr.Spec.SecretNamespace != "" && cr.Spec.SecretNamespace != cr.Namespace {
    if err := r.RBACScoper.EnsureAccessInNamespace(
        ctx, cr, cr.Spec.SecretNamespace,
    ); err != nil {
        return ctrl.Result{}, fmt.Errorf("ensuring cross-NS access: %w", err)
    }
}

// Updated deletion:
if err := r.RBACScoper.CleanupAllAccess(ctx, cr); err != nil {
    return ctrl.Result{}, fmt.Errorf("cleanup: %w", err)
}
```

#### 5.3 `examples/operator/api/v1alpha1/exampleresource_types.go`

**Changes:**

- Add `SecretNamespace` field to `ExampleResourceSpec` to demonstrate
  cross-namespace configuration:

```go
type ExampleResourceSpec struct {
    // SecretNamespace is the namespace where secrets are stored.
    // If empty, defaults to the CR's own namespace.
    // +optional
    SecretNamespace string `json:"secretNamespace,omitempty"`
}
```

- Regenerate deepcopy: `make generate`

#### 5.4 `examples/operator/internal/controller/exampleresource_controller_test.go`

**Changes:**

- Replace all `&rbacscope.RBACScoper{...}` struct initializations with
  `rbacscope.NewRBACScoper(...)` constructor (3 occurrences: lines 56-67,
  197-208, 273-284)
- Add test for cross-namespace access:
  - Create CR with `SecretNamespace: "remote-ns"`
  - Verify Role and RoleBinding created in `remote-ns`
  - Verify annotation-based ownership on the Role in `remote-ns`
- Add test for cross-namespace cleanup:
  - Create CR with cross-NS access
  - Delete CR
  - Verify Role in remote NS is cleaned up via annotation removal
- Update deletion test to use `CleanupAllAccess` instead of `CleanupAccess`

#### 5.5 `examples/operator/demo/README.md`

**Changes:**

- Add section "Cross-Namespace Demo" describing how the demo shows:
  - CR with `SecretNamespace` creates a Role in the remote namespace
  - CR deletion cleans up the remote Role
  - Remote namespace secrets access is only available when CR is active

#### 5.6 `pkg/rbacscope/rbac_scoper_test.go`

**Changes:**

- Replace all `&RBACScoper{...}` struct initializations with
  `NewRBACScoper(...)` constructor (affects `newTestScoper` helper and
  direct instantiations in `TestEnsureAccess_CustomRules`,
  `TestEnsureAccess_MultiResourceRules`, `TestEnsureAccess_RuleUpdateConvergence`,
  `TestEnsureAccess_ValidationErrors`)
- Update `TestEnsureAccess_ValidationErrors` to test constructor validation
  (constructor returns error instead of runtime validation)
- Add tests for:
  - `NewRBACScoper` with options (`WithDeniedNamespaces`,
    `WithAggregationLabelCheck`)
  - `EnsureAccessInNamespace` creates Role in target namespace
  - `EnsureAccessInNamespace` denied for default denied namespaces
  - `CleanupAllAccess` removes owner from all managed resources
  - Multi-owner cross-namespace scenarios
  - AllowedRules ceiling enforcement
  - Orphan GC

### Phase 6: Verification

1. Run `go build ./...` across the entire module
2. Run `go test ./pkg/... -v -count=1` for library tests
3. Run `go test ./examples/... -v -count=1` for example operator tests
4. Run `go vet ./...` for static analysis
5. Verify all documentation code examples compile (extract and test)
6. Review all Mermaid diagrams render correctly

---

## 12. Testing Strategy

### Unit Tests

- `NewRBACScoper` validation (required fields, AllowedRules, options)
- `EnsureAccessInNamespace` creates Role/RoleBinding in target namespace
- `EnsureAccessInNamespace` denied for system namespaces
- `CleanupAllAccess` removes owner from all managed resources
- `ClusterRBACScoper.EnsureClusterAccess` creates ClusterRole/ClusterRoleBinding
- `ClusterRBACScoper.CleanupClusterAccess` annotation-based cleanup
- Multi-owner scenarios (two CRs → shared Role → one deleted → Role persists)
- Orphan GC (owner annotation references non-existent CR)
- AllowedRules ceiling enforcement (requested rules exceed ceiling → error)
- DeniedNamespaces enforcement
- Aggregation label check

### Integration Tests

- End-to-end CR lifecycle with cross-namespace access
- Concurrent reconcilers updating shared annotations
- Force-deleted CR → orphan GC cleans up

---

## 13. Coverage Summary

| Pattern | Today | After This Design | Mechanism |
|---------|-------|-------------------|-----------|
| 5. Same-NS resource access | Covered | Covered | `EnsureAccess(ctx, cr)` |
| 1. Fixed infra NS | Not covered | **Covered** | `EnsureAccessInNamespace(ctx, cr, "openshift-ingress")` |
| 2. User-configurable NS | Not covered | **Covered** | `EnsureAccessInNamespace(ctx, cr, cr.Spec.SecretNS)` |
| 3. Operator NS | Not covered | **Covered** | `EnsureAccessInNamespace(ctx, cr, os.Getenv("POD_NS"))` |
| 4c. CR instance discovery | Not covered | **Covered** | `ClusterRBACScoper.EnsureClusterAccess(ctx, cr)` |
| 4c. CR instance access | Not covered | **Covered** | `EnsureAccessInNamespace(ctx, cr, foundNS)` |
| 4a. CRD existence check | Not covered | Docs only | Static ClusterRole (irreducible minimum) |
| 4b. Cluster resource collection | Not covered | Docs only | Static ClusterRole (irreducible minimum) |

---

## Appendix A: Complete File Change Inventory

Every file that must be created, modified, or reviewed during implementation.

### New Files (Create)

| File | Phase | Purpose |
|------|-------|---------|
| `pkg/rbacscope/option.go` | 1 | `Option` interface, `optionFunc`, `WithDeniedNamespaces`, `WithAggregationLabelCheck` |
| `pkg/rbacscope/identity.go` | 1 | `OperatorIdentity`, `AllowedRules`, `NewAllowedRules`, `AllowAllRules` |
| `pkg/rbacscope/helpers.go` | 2 | `annotationOwnerTracker`, `cleanupOwnedResource`, shared helpers |
| `pkg/rbacscope/cluster_rbac_scoper.go` | 3 | `ClusterRBACScoper`, `NewClusterRBACScoper`, `EnsureClusterAccess`, `CleanupClusterAccess` |
| `pkg/rbacscope/cluster_rbac_scoper_test.go` | 3 | Tests for `ClusterRBACScoper` |

### Modified Files (Source Code)

| File | Phase | Changes |
|------|-------|---------|
| `pkg/rbacscope/rbac_scoper.go` | 1-2 | Make fields unexported; add `NewRBACScoper` constructor; extract `cleanupOwnedResource`, `recreateRoleBinding`; add `EnsureAccessInNamespace`, `CleanupAllAccess`; add `scopeConfig` internal struct |
| `pkg/rbacscope/rbac_scoper_test.go` | 1-2 | Migrate to `NewRBACScoper`; add cross-NS tests, `AllowedRules` ceiling tests, `DeniedNamespaces` tests, orphan GC tests |
| `pkg/rbacscope/doc.go` | 4 | Replace package godoc with new API examples |
| `examples/operator/cmd/main.go` | 5 | Replace `&rbacscope.RBACScoper{...}` with `NewRBACScoper(...)` constructor; add error handling |
| `examples/operator/internal/controller/exampleresource_controller.go` | 5 | Add `EnsureAccessInNamespace` for cross-NS; change `CleanupAccess` to `CleanupAllAccess`; update RBAC markers |
| `examples/operator/internal/controller/exampleresource_controller_test.go` | 5 | Migrate to `NewRBACScoper`; add cross-NS tests; update deletion test |
| `examples/operator/api/v1alpha1/exampleresource_types.go` | 5 | Add `SecretNamespace` field to `ExampleResourceSpec` |
| `examples/operator/api/v1alpha1/zz_generated.deepcopy.go` | 5 | Regenerate via `make generate` |

### Modified Files (Documentation)

| File | Phase | Changes |
|------|-------|---------|
| `README.md` | 4 | Update Quick Start examples to constructor API; add cross-NS and cluster-scoped Quick Start sections; add Mermaid diagrams; update How It Works table; update Defense in Depth |
| `docs/TECHNICAL_DESIGN.md` | 4 | Add cross-NS scoping subsection; add cluster-scoped subsection; add security model subsection; update CR lifecycle Mermaid diagram; expand escalate verb section; add architectural tradeoffs; update coverage table |
| `docs/INTEGRATION_GUIDE.md` | 4 | Update Section 3.1 to constructor; add cross-NS walkthrough (Section 3.X); add cluster-scoped walkthrough (Section 3.Y); add security config section (Section 3.Z); add constructor migration guide (Section 5.X); add troubleshooting entries; update RBAC markers |
| `examples/operator/demo/README.md` | 5 | Add cross-namespace demo section |

### Unchanged Files (No Modifications Needed)

| File | Reason |
|------|--------|
| `pkg/saprotection/*.go` | SA protection is independent; no API changes |
| `pkg/impersonationguard/*.go` | Impersonation guard is independent; no API changes |
| `pkg/rbacaudit/*.go` | RBAC audit is independent; no API changes |
| `examples/operator/attack/README.md` | Attack demo is SA-focused, not RBAC scoping |
| `config/validatingadmissionpolicy/*.yaml` | Impersonation policy, unrelated |
