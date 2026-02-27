# Impersonation Guard — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Block `kubectl --as=system:serviceaccount:<ns>:<sa>` impersonation attacks that bypass the SA protection webhook.

**Architecture:** A reconciler controller that strips `impersonate` from `system:aggregate-to-edit` ClusterRole + a ValidatingAdmissionPolicy to prevent new impersonation grants + a startup RBAC audit function.

**Tech Stack:** Go, controller-runtime, Kubernetes RBAC API, ValidatingAdmissionPolicy (K8s 1.30+)

---

## Problem Statement

The existing SA protection webhook (`pkg/saprotection`) blocks unauthorized pod creation using operator ServiceAccounts. However, Kubernetes impersonation bypasses this entirely:

```bash
kubectl --as=system:serviceaccount:operator-ns:operator-sa get secrets -A
```

This works because:

1. **Impersonation is processed at the authentication layer**, before admission webhooks fire. Webhooks cannot detect or intercept impersonation (confirmed by rejected upstream PR kubernetes/kubernetes#133825).

2. **`system:aggregate-to-edit` ClusterRole grants `impersonate` on `serviceaccounts` by default.** This role aggregates into `edit` and `admin`, meaning any namespace editor can impersonate any SA in their namespace.

This is the same attack vector that led to the original security issue — the user discovered it by impersonating the operator SA to access secrets cluster-wide.

## Scope

**In scope:**
- Impersonation guard reconciler (`pkg/impersonationguard`)
- Startup RBAC audit function
- ValidatingAdmissionPolicy YAML artifacts
- Documentation fixes (correct incorrect claims about impersonation defaults)

**Out of scope:**
- TokenRequest webhook (dropped — `failurePolicy:Fail` on token requests causes cascading cluster failures)
- Workload SA management (documented as a pattern in Integration Guide, not library code)

## Design

### Component 1: ImpersonationGuard Reconciler

**Package:** `pkg/impersonationguard`

A controller-runtime reconciler that watches the `system:aggregate-to-edit` ClusterRole and strips the `impersonate` verb from any rule targeting `serviceaccounts`.

#### Behavior

1. On startup and on any change to `system:aggregate-to-edit`, the reconciler reads the ClusterRole
2. Scans all rules for `impersonate` verb on `serviceaccounts` resource
3. If found, removes the verb (or the entire rule if `impersonate` was the only verb)
4. Sets annotation `rbac.authorization.kubernetes.io/autoupdate: "false"` to prevent the Kubernetes RBAC controller from re-adding the rule on API server restart
5. Updates the ClusterRole

#### Struct

```go
type ImpersonationGuardReconciler struct {
    client.Client
    Scheme *runtime.Scheme
}
```

#### Key Design Decisions

- **Why a reconciler, not a one-shot?** The `autoupdate: false` annotation prevents automatic restoration, but a cluster admin could manually re-add the verb, or a different controller could modify the ClusterRole. The reconciler ensures continuous enforcement.

- **Why `system:aggregate-to-edit` specifically?** This is the root ClusterRole that aggregates into `edit` and `admin`. Stripping here propagates to all aggregated roles automatically.

- **Why not strip from `edit`/`admin` directly?** Those are aggregate roles — their rules come from label-selected ClusterRoles. Modifying them directly would be overwritten by the aggregation controller.

- **What about legitimate impersonation users?** Cluster-admins retain impersonation via the `cluster-admin` role, which is not affected. Any service that needs impersonation can be granted it via a separate, explicit ClusterRoleBinding — the guard only removes the *default* grant to editors.

#### Predicate Filter

The reconciler uses a predicate to only process events for the `system:aggregate-to-edit` ClusterRole:

```go
func (r *ImpersonationGuardReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&rbacv1.ClusterRole{}, builder.WithPredicates(predicate.NewPredicateFuncs(
            func(obj client.Object) bool {
                return obj.GetName() == "system:aggregate-to-edit"
            },
        ))).
        Complete(r)
}
```

#### Upgrade Survivability

| Scenario | Behavior |
|----------|----------|
| K8s upgrade re-adds rule | `autoupdate: false` prevents this. If annotation is lost, reconciler re-strips on next event. |
| Admin manually re-adds verb | Reconciler detects change event and re-strips. |
| Another controller modifies ClusterRole | Reconciler detects change event and re-strips. |
| Guard reconciler is disabled/removed | `autoupdate: false` annotation persists, preventing restoration until someone manually removes it and triggers an API server restart. |

#### RBAC Requirements

The reconciler needs:
```yaml
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["get", "list", "watch", "update", "patch"]
  resourceNames: ["system:aggregate-to-edit"]
```

### Component 2: Startup RBAC Audit

**Package:** `pkg/rbacaudit`

A function called during operator startup that checks for impersonation and token request exposure, logging warnings.

```go
func AuditImpersonationExposure(ctx context.Context, c client.Client) []Finding
```

#### Checks

1. **`system:aggregate-to-edit` contains `impersonate`** — warns that editors can impersonate SAs
2. **ClusterRoleBindings granting `serviceaccounts/token` create** — warns about token minting exposure
3. **Custom ClusterRoles with `impersonate` on `serviceaccounts`** — warns about non-default impersonation grants

#### Output

Returns a slice of `Finding` structs that callers can log, emit as events, or report to monitoring:

```go
type Finding struct {
    Severity    string // "critical", "warning", "info"
    Category    string // "impersonation", "token-request"
    Resource    string // e.g., "ClusterRole/system:aggregate-to-edit"
    Description string
}
```

### Component 3: ValidatingAdmissionPolicy Artifacts

**Directory:** `config/validatingadmissionpolicy/`

YAML artifacts (not Go code) that operators can deploy to prevent non-system users from creating new ClusterRoles or Roles containing the `impersonate` verb. This blocks circumvention via custom roles.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-impersonate-grants
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["rbac.authorization.k8s.io"]
        apiVersions: ["v1"]
        resources: ["clusterroles", "roles"]
        operations: ["CREATE", "UPDATE"]
  matchConditions:
    - name: not-system-user
      expression: "!request.userInfo.username.startsWith('system:')"
  validations:
    - expression: |
        !object.rules.exists(r,
          r.verbs.exists(v, v == 'impersonate') &&
          r.resources.exists(res, res == 'serviceaccounts' || res == '*')
        )
      message: "Granting 'impersonate' on serviceaccounts is restricted. Contact your cluster admin."
```

Requires K8s 1.30+ / OCP 4.17+. Operators on older versions rely on the reconciler alone.

### Integration

All three components are independently usable:

```go
// In main.go:

// 1. Run startup audit (optional)
findings := rbacaudit.AuditImpersonationExposure(ctx, mgr.GetClient())
for _, f := range findings {
    setupLog.Info("RBAC audit finding", "severity", f.Severity, "description", f.Description)
}

// 2. Register impersonation guard (optional)
if err := (&impersonationguard.ImpersonationGuardReconciler{
    Client: mgr.GetClient(),
    Scheme: mgr.GetScheme(),
}).SetupWithManager(mgr); err != nil {
    setupLog.Error(err, "unable to create impersonation guard")
    os.Exit(1)
}

// 3. Deploy ValidatingAdmissionPolicy YAML (optional, K8s 1.30+)
// kubectl apply -f config/validatingadmissionpolicy/
```

### Documentation Fixes

The `TECHNICAL_DESIGN.md` currently states that impersonation is NOT in default Kubernetes roles. This is incorrect — `system:aggregate-to-edit` grants it by default. Fix all instances:

- `docs/TECHNICAL_DESIGN.md` — correct the impersonation section
- `docs/INTEGRATION_GUIDE.md` — update Section 6 (Complementary RBAC Hardening) with the correct threat assessment

## Future: KEP-5284 Constrained Impersonation

Kubernetes KEP-5284 introduces constrained impersonation at the API server level (alpha in K8s 1.35, estimated OpenShift availability ~4.22+, ~2027). Once available, the impersonation guard reconciler becomes unnecessary — operators can use the native constraint mechanism instead. The library should document the migration path when KEP-5284 reaches beta.
