# Operator Security Runtime: Architect Presentation Material

> Reviewed by 5 independent architect personas: Security Accuracy, Technical Correctness, Completeness, Narrative Structure, Adversarial Questioning.

---

## 1. The Problem

Any user with `edit` in a namespace where an RHOAI operator runs can read every Secret in the cluster. Today. In production. This is not a misconfiguration. It is a design gap in Kubernetes RBAC that has been open since 2015.

### Why This Happens

Kubernetes RBAC has no field-level restriction on `spec.serviceAccountName` during pod creation. The standard `edit` ClusterRole allows any namespace editor to create pods referencing **any** ServiceAccount in their namespace, including highly-privileged operator ServiceAccounts. The pod inherits all RBAC permissions of that SA.

kubernetes#17637 (2015) proposed a `use` verb for ServiceAccount authorization during pod creation, but the enforcement mechanism was only implemented for PodSecurityPolicy (now deprecated and removed in v1.25). No general-purpose SA usage restriction exists in upstream Kubernetes.

### Scale of Exposure

Unit 42 research found:
- 62.5% of Kubernetes platforms had privileged credentials on every node
- 50% allowed a single container escape to escalate to full cluster compromise

RHOAI operators use static ClusterRoles granting cluster-wide secrets access. A single `edit` user in any namespace can access secrets across **all** namespaces by creating a pod with an operator SA.

---

## 2. The Library: operator-security-runtime

Four independent, composable packages:

| Package | Controls | Mechanism |
|---------|----------|-----------|
| `pkg/saprotection` | **WHO** can use the SA | ValidatingWebhook on Pod CREATE/UPDATE |
| `pkg/rbacscope` | **WHERE** the SA has permissions | Dynamic Roles/ClusterRoles tied to CR lifecycle |
| `pkg/impersonationguard` | **HOW** identity can be assumed | Reconciler strips impersonate from system:aggregate-to-edit |
| `pkg/rbacaudit` | **WHAT** exposure exists | Startup RBAC scan for impersonation/token vectors |

### Defense-in-Depth Matrix

| Attack Vector | saprotection | rbacscope | impersonationguard | rbacaudit |
|---------------|:---:|:---:|:---:|:---:|
| Pod SA hijacking | Blocks | Limits blast radius | - | - |
| SA impersonation | - | Limits blast radius | Blocks | Detects |
| Token leak/compromise | - | Limits blast radius | - | - |
| TokenRequest API abuse | - | Limits blast radius | - | Detects |
| ClusterRole aggregation bypass | - | - | Blocks | Detects |

### RBAC Scoping Variants

| Variant | Manages | Ownership | Use Case |
|---------|---------|-----------|----------|
| `RBACScoper.EnsureAccess` | Role + RoleBinding in CR namespace | OwnerReferences | Same-namespace access |
| `RBACScoper.EnsureAccessInNamespace` | Role + RoleBinding in arbitrary namespace | Annotation-based | Cross-namespace access |
| `ClusterRBACScoper.EnsureAccess` | ClusterRole + ClusterRoleBinding | Annotation-based | Cluster-scoped resources (nodes, PVs) |

Cross-namespace grants enforce a denied-namespace list (default: `kube-system`, `kube-public`, `kube-node-lease`, `default`, `openshift-*` prefix). Both scopers satisfy the `AccessScoper` interface, enabling generic middleware and test mocks.

### Imperative Execution Model

rbacscope uses an imperative model: `EnsureAccess` and `CleanupAccess` are utility functions called by the caller's reconciler. The library does not register controllers, watches, or informers on managed RBAC resources.

| Property | rbacscope | impersonationguard |
|----------|-----------|-------------------|
| Execution model | Imperative (caller invokes) | Controller (own reconcile loop) |
| Watch streams | 0 | 1 (system:aggregate-to-edit) |
| Informer cache | None for RBAC resources | 1 ClusterRole |
| Drift recovery | Next CR reconcile | Immediate (watch-triggered) |
| Extensibility | Caller adds `Owns()` for immediate recovery | N/A (self-contained) |

This design is intentional: RBAC resources are tied to CR lifecycle, so they only need correction when the CR is reconciled. impersonationguard watches a ClusterRole because external actors (cluster upgrades) can revert it at any time, independent of CR events.

---

## 3. CVEs and Incidents We Address

### Direct Relevance

**CVE-2025-1974 -- IngressNightmare (CVSS 9.8)**
Compromised ingress-nginx SA gave cluster-wide secrets access. Our library: `saprotection` blocks unauthorized SA usage; `rbacscope` limits secrets access to namespaces with active CRs. If the operator SA had been scoped, blast radius would have been a single namespace.

**CVE-2024-43403 -- Kanister (CVSS 8.8)**
`system:aggregate-to-edit` granted `impersonate` + `create serviceaccounts/token` to every namespace editor via aggregation into `edit`/`admin`. Our library: `impersonationguard` strips the impersonate verb; `rbacaudit` detects token-request exposure at startup.

**CVE-2021-25740 -- Endpoints/EndpointSlice (CVSS 3.1)**
Overly permissive verb aggregation in `system:aggregate-to-edit` allowed cross-namespace traffic forwarding via Endpoints write access. While `impersonationguard` addresses the impersonation verb specifically, this CVE illustrates the broader pattern of dangerous default aggregation that the library's design philosophy is built to address.

**GCP-2023-047 -- GKE Fluent Bit Privilege Escalation**
Compromised FluentBit DaemonSet SA had cluster-wide permissions enabling escalation to full cluster compromise. `rbacscope` would have limited the SA to namespaces with active CRs.

SA token abuse is a documented vector in campaigns like TeamTNT's Hildegard (2021), Siloscape (2021, first K8s-targeting Windows malware), and BishopFox's Bad Pods research (8 pod privilege escalation paths).

---

## 4. Novelty: No Open-Source Equivalent Exists

### Cloud Provider Comparison

All three major cloud providers have implemented internal admission control mechanisms to protect their own system-level ServiceAccounts. None offer these as reusable libraries for customer operators:

| Provider | Internal Protection | Available to Customers? |
|----------|-------------------|------------------------|
| **EKS** | Internal validating webhooks for system node components | No |
| **AKS** | `aks-node-validating-webhook` restricting node modifications | No |
| **GKE** | Architectural permission scoping (post GCP-2023-047) | No |
| **Our library** | Reusable SA protection + dynamic RBAC scoping | **Yes (open-source)** |

### The Upstream Gap

- kubernetes#17637 (2015): proposed SA `use` verb enforcement, only implemented for PSP (now removed)
- KEP-5284 (Constrained Impersonation): reached alpha in Kubernetes 1.34, targeting beta in 1.36. Until GA and enabled by default, the gap persists in production clusters. Even at GA, KEP-5284 addresses impersonation only, not SA-in-pod-spec restriction.
- **Our library addresses a gap that neither kubernetes#17637 (PSP-focused, now removed) nor KEP-5284 (impersonation-focused, still alpha) was designed to fully solve.**

---

## 5. The `escalate` Trade-off

### The Concern

Replacing `secrets: get/list/watch` in the operator's ClusterRole with `roles: escalate` trades one privilege for another. The `escalate` verb allows creating Roles that grant permissions the creator does not itself hold, bypassing the standard RBAC escalation prevention check.

### Why `escalate` Is Preferable

| Dimension | Static secrets access | escalate + dynamic scoping |
|-----------|----------------------|---------------------------|
| **Blast radius** | All namespaces, always | Only namespaces with active CRs |
| **Temporal scope** | Permanent | CR lifecycle-bound |
| **Exercise path** | Any API call | Only through reconciler code |
| **Audit trail** | No specific trigger | CR creation/deletion events |
| **Principle of least privilege** | Violates (cluster-wide) | Follows (namespace-scoped, on-demand) |

### The Trigger Difference

CR-based trigger (our library):
- Roles created only when CRs exist (small subset of namespaces)
- No new permissions when a plain namespace is created

Namespace-based trigger (alternative approach):
- Roles created in every new namespace
- For namespace-scoped resources, equivalent to a ClusterRole in steady state

### Addressing the Theoretical Maximum

Yes, `escalate` permits creating Roles with arbitrary permissions. However, the operator's reconciler code is the only code path that exercises this verb. The Roles created are deterministic: they contain exactly the `PolicyRules` configured at construction time. An attacker would need to compromise the operator's source code or binary to change what Roles are created. At that point, any permission model is defeated. The relevant comparison is: "what can an unprivileged namespace editor do without compromising the operator?" In that comparison, escalate+scoping is strictly better.

---

## 6. `system:aggregate-to-edit`: A Recurring Pattern

### The Chain

1. `system:aggregate-to-edit` has label `aggregate-to-edit: "true"`
2. Kubernetes aggregation merges its rules into `edit` ClusterRole
3. `edit` aggregates into `admin`
4. Any user with `edit` or `admin` gets `impersonate` on `serviceaccounts`
5. User runs `kubectl --as=system:serviceaccount:ns:operator-sa`
6. API server processes impersonation at authentication layer (before webhooks)
7. Webhook sees the impersonated identity, not the real caller
8. SA protection is bypassed

> **Note:** Verify whether your target platform (OpenShift/OKD) includes `impersonate` in `system:aggregate-to-edit` by default. The default rules vary by distribution and version.

### Multiple CVEs from This Pattern

- CVE-2024-43403 (Kanister): impersonate + token create via aggregate-to-edit
- CVE-2021-25740 (Endpoints): Endpoints write via aggregate-to-edit
- CVE-2020-8554 (ExternalIP): Service ExternalIP man-in-the-middle via aggregate-to-edit

The pattern keeps producing vulnerabilities because the upstream defaults have not been hardened.

### Our Fix

`impersonationguard` reconciler:
- Strips `impersonate` from `system:aggregate-to-edit`
- Sets `autoupdate: "false"` to prevent RBAC controller from restoring it
- Companion ValidatingAdmissionPolicy (K8s 1.30+) blocks new RBAC resources granting impersonate

---

## 7. Operational Concerns

### Total Cost of Ownership

| Dimension | Cost |
|-----------|------|
| **New resources per namespace** | 1 Role + 1 RoleBinding (deterministically cleaned up on CR deletion) |
| **Cluster-wide resources** | 1 ValidatingWebhookConfiguration, 1 ValidatingAdmissionPolicy (optional), ImpersonationGuard watches 1 ClusterRole |
| **rbacscope watch overhead** | Zero. Imperative model — no watches, no informers, no additional memory for RBAC resources. Drift corrected on next reconcile |
| **TLS** | Standard controller-runtime webhook serving; works with cert-manager or OLM-managed certificates |
| **GC** | Optional `GarbageCollectOrphanedOwners`, recommended on leader election start. Paginated (100/page) |
| **Integration effort** | One-time per operator: add 3 calls (`EnsureAccess`, `CleanupAccess`, register webhook) |
| **Webhook latency** | ~1-5ms per pod creation (string comparison, no external calls). SA-unchanged updates short-circuited |

### Webhook Availability

`failurePolicy: Fail` means webhook unavailability blocks pod creation (fail-secure). This is the single biggest operational concern.

**Mitigations:**
- 3+ replicas with pod anti-affinity (`requiredDuringSchedulingIgnoredDuringExecution`)
- PodDisruptionBudget with `minAvailable: 2`
- Operator namespace excluded from webhook `namespaceSelector` (prevents deadlock: webhook pod can always restart)

**Break-glass procedure:**
`kubectl delete validatingwebhookconfiguration <name>` immediately restores pod creation. Document this in runbooks.

**Deadlock prevention:** If the operator namespace is NOT excluded from the webhook's `namespaceSelector`, the operator pod cannot restart (its creation triggers the webhook, which is down). Always exclude the operator namespace.

### GitOps Compatibility

Dynamically created Roles and RoleBindings are operator-managed, not GitOps-managed. Exclude them from ArgoCD/Flux sync via resource exclusion rules. The operator's static ClusterRole (which IS GitOps-managed) no longer contains scoped resource permissions, so there is no drift. The `impersonationguard` reconciler modifies `system:aggregate-to-edit`, a Kubernetes default: exclude from GitOps management or coordinate with the platform team.

### Emergency Override

Cluster administrators can bypass the webhook by: (1) temporarily deleting the `ValidatingWebhookConfiguration`, (2) creating pods in the operator's namespace (excluded from scope), or (3) re-granting impersonate temporarily. All override actions are auditable via Kubernetes audit logs. The absence of a built-in bypass is intentional: bypass should be deliberate and auditable, not convenient.

---

## 8. API Design Highlights

**Constructor validation:** Both `NewRBACScoper` and `NewClusterRBACScoper` validate all identity fields against DNS-1123 at construction time. Invalid inputs produce descriptive errors before any RBAC operations occur.

**Functional options:** `WithDeniedNamespaces`, `WithAdditionalDeniedNamespaces` configure cross-namespace restrictions. Post-option validation catches zero-arg calls and empty strings.

**DeferToStaticRBAC:** For operators with properly constrained static RBAC that only need lifecycle tracking, `DeferToStaticRBAC()` creates Roles with zero rules for ownership tracking without altering the permission model.

**RoleBinding drift recovery:** The `roleRef` field is immutable in Kubernetes. If it doesn't match, the scoper deletes and recreates the binding. rbacscope itself does not watch RBAC resources — drift is corrected on the next CR reconcile via idempotent `EnsureAccess`. Callers can optionally add `Owns(&Role{})` / `Owns(&RoleBinding{})` in their `SetupWithManager` to trigger immediate re-reconciliation on external changes.

**Annotation-based ownership:** Cross-namespace and cluster-scoped grants use a custom annotation (`opendatahub.io/scoped-access-owners`) with comma-separated `namespace/name/uid` entries. Corruption-resilient parsing handles trailing commas, empty entries, and malformed data.

---

## 9. Test Coverage

- **Unit tests:** ~4,970 lines of test code across all four packages
- **rbacscope:** ~3,700 lines covering multi-CR ownership, annotation corruption (8 subtests), cross-namespace grants, GC, DNS-1123 validation, RoleBinding drift recovery, paginated listing
- **Integration:** Controller test suite using envtest (real API server, no mocks)
- **Example operator:** Complete working operator in `examples/operator/` as reference implementation
- **Adoption safety:** The library is additive. `EnsureAccess` and `CleanupAccess` are called alongside existing business logic. The migration path ensures zero downtime by keeping the static ClusterRole as fallback until scoped Roles are verified.

---

## 10. Anticipated Questions

### Security

**Q: What if the operator itself is compromised?**
A: `rbacscope` limits blast radius. A compromised operator with dynamic scoping can only access secrets in namespaces with active CRs, not cluster-wide.

**Q: Doesn't `escalate` just trade one powerful permission for another?**
A: See Section 5. `escalate` is exercised only through reconciler code, never directly by users. The temporal and namespace scoping make it strictly better than static cluster-wide access.

**Q: What about TokenRequest API bypass?**
A: A user with `create` on `serviceaccounts/token` can mint tokens without creating a pod. `rbacscope` limits what that token can access. `rbacaudit` detects this exposure at startup.

**Q: Can impersonation still bypass the webhook?**
A: Not with `impersonationguard` active. The reconciler strips `impersonate` from `system:aggregate-to-edit`, and the ValidatingAdmissionPolicy prevents new grants.

**Q: What if someone edits the ownership annotation to prevent cleanup?**
A: `GarbageCollectOrphanedOwners` resolves each entry against the actual CR via callback. Fake entries pointing to non-existent CRs are detected and removed.

### Operations

**Q: What happens if the webhook is down?**
A: `failurePolicy: Fail` blocks pod creation (fail-secure). Break-glass: delete the `ValidatingWebhookConfiguration`. See Section 7.

**Q: You block cluster-admin from creating pods with the operator SA. How do ops teams intervene?**
A: See Emergency Override in Section 7. All overrides are deliberate and auditable.

**Q: How does migration work without downtime?**
A: Three-step: (1) deploy scoper + keep static ClusterRole as fallback, (2) verify all CRs reconciled, (3) remove scoped resources from static ClusterRole.

**Q: What about orphaned RBAC resources?**
A: `GarbageCollectOrphanedOwners` scans managed resources and removes stale entries. Paginated (100/page). Call on leader election start or periodic timer.

### "Why Not X?"

**Q: Why not just restrict the `edit` ClusterRole?**
A: Breaks standard user workflows. Users need pod creation for legitimate workloads.

**Q: Why not OPA/Gatekeeper?**
A: OPA can enforce admission policies (SA restriction via Rego) but cannot perform dynamic RBAC scoping or CR lifecycle management. Requires maintaining Rego policies per operator.

**Q: Why not Kyverno?**
A: Kyverno can validate pod SA fields and generate resources, but its generate rules do not support CR-lifecycle-bound RBAC. For SA protection alone it could work, but requires maintaining Kyverno as a platform dependency.

**Q: Why not native ValidatingAdmissionPolicy (CEL)?**
A: CEL policies (K8s 1.30+) can check pod SA fields but cannot do dynamic RBAC scoping or lifecycle management. The impersonation guard's companion policy already uses this mechanism where appropriate.

**Q: Kubernetes will eventually fix this upstream, why build a library?**
A: kubernetes#17637 was filed in 2015 and the SA restriction was never built. KEP-5284 is alpha, addresses only impersonation, and will take years to reach GA. The gap exists today.

### Design Philosophy

**Q: Why a library instead of a platform feature?**
A: Each operator has different permission profiles, CRs, and lifecycle patterns. A library lets each team own their security posture independently. A platform-wide webhook would require every operator team to coordinate on a single deployment.

**Q: Can I adopt just one package?**
A: Yes. Minimum viable adoption: add `pkg/saprotection` only (~5 lines of code + webhook configuration). No finalizers, no RBAC changes. Total effort: <1 hour for an operator already using controller-runtime webhooks.

**Q: Does rbacscope add watch streams or informer cache overhead?**
A: No. rbacscope is imperative — `EnsureAccess`/`CleanupAccess` are called inline during reconciliation. Zero additional watch streams, zero informer cache for RBAC resources. Drift recovery happens on the next reconcile cycle. Callers who need immediate drift recovery can add `Owns(&rbacv1.Role{})` and `Owns(&rbacv1.RoleBinding{})` in their `SetupWithManager` — a standard controller-runtime pattern that the library does not impose.

**Q: What about versioning and API stability?**
A: The library is pre-1.0 (`v0.x`). The `AccessScoper` interface and `ProtectedIdentity` struct are stable. Breaking changes are documented in commit messages with migration guidance.

**Q: This seems RHOAI-specific. Is it generalizable?**
A: Zero RHOAI-specific code. Depends only on `controller-runtime`, `client-go`, and standard Kubernetes APIs. The CVEs cited affect operators from completely different ecosystems. The library is as generalizable as the problem.

### What This Does NOT Solve

This library operates at the RBAC layer only. It does not protect against compromised etcd, does not replace network policies, and does not address container escape vulnerabilities. It does not cover operators without CRs (e.g., Dashboard needs a different approach).

---

## 11. Integration Status

| Team | CR Type | Scoped Resources | Integration Path |
|------|---------|-------------------|-----------------|
| DSPO | DSPA | secrets | Validated |
| Notebooks | Notebook | secrets | Validated |
| Ray | RayCluster | secrets | Validated |
| Feast | FeatureStore | secrets | Validated |
| Model Controller | InferenceService | secrets, configmaps | Validated |
| Dashboard | N/A (no CR) | secrets | Needs different approach |
| Model Registry | N/A | N/A | Not applicable |

---

## 12. Summary

1. **The gap is real, exploited, and unfixed upstream since 2015.** CVE-2025-1974 (9.8 CVSS), CVE-2024-43403 (8.8 CVSS), multiple real-world incidents. No KEP or upstream fix addresses SA-in-pod-spec restriction.

2. **We are the first open-source library to fill it.** Every major cloud provider built internal equivalents but none are reusable. Four composable packages, any operator can adopt incrementally.

3. **Minimal operational cost, maximum blast radius reduction.** ~1-5ms webhook latency, 1 Role + 1 RoleBinding per namespace with a CR, standard controller-runtime conventions, cert-manager for webhook TLS.

---

## Appendix A: Security Framework Alignment

| Framework | Control | Library Coverage |
|-----------|---------|-----------------|
| **CIS Kubernetes Benchmark** | 5.1.2: Minimize access to secrets / 5.1.5: Default SAs not actively used | saprotection restricts SA usage; rbacscope minimizes secrets access scope |
| **NIST SP 800-190** | 3.3.1: Container runtime privileges / 4.3.1: Runtime access controls | rbacscope implements runtime access controls |
| **NSA/CISA Hardening Guide v1.2** | SA hardening, least privilege | All four packages |
| **OWASP Kubernetes Top 10** | K03: Overly permissive RBAC / K06: Broken authentication | rbacscope (K03), saprotection+impersonationguard (K06) |

### MITRE ATT&CK for Containers

| Technique | ID | Library Mitigation |
|-----------|-----|-------------------|
| Valid Accounts: Cloud Accounts | T1078.004 | saprotection blocks SA hijacking |
| Account Manipulation: Additional Container Cluster Roles | T1098.006 | impersonationguard strips impersonate; VAP blocks new grants |
| Unsecured Credentials: Container API | T1552.007 | rbacscope limits what leaked tokens can access |
| Use Alternate Authentication Material | T1550.001 | saprotection validates pod creator identity |
| Deploy Container | T1610 | saprotection blocks unauthorized pod creation with operator SA |
