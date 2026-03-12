# Speaker Notes — operator-security-runtime Presentation

## How to Use These Notes

Each slide has:
- **Duration**: Target time per slide (total: ~40 minutes + 15 minutes Q&A)
- **Key message**: The ONE thing the audience must remember from this slide
- **Talking points**: What to say (in order)
- **Transition**: How to bridge to the next slide

---

## Slide 1: Title (1 min)

**Key message**: This is a security architecture proposal requesting a specific decision.

**Talking points**:
- "Thank you for the time. I'm here to present operator-security-runtime — a library we've built to close a known privilege escalation path in our operators."
- "Two CVEs frame this talk: CVE-2024-43403 demonstrated how easy the escalation path is — one kubectl command via aggregate-to-edit. CVE-2025-1974 demonstrated the catastrophic impact when an operator SA is compromised — full cluster takeover."
- "The ask is specific: approve this as a recommended library and greenlight a pilot with rbacaudit across 2-3 operators."
- "I'll walk through the threat, the solution, the trade-offs, and the operational readiness — and then we'll discuss."

**Transition**: "Let me start with why this matters now."

---

## Slide 2: Executive Summary (2 min)

**Key message**: There is a known, exploitable attack path in every operator we ship. This library closes it.

**Talking points**:
- State the problem in one sentence: "Every operator that manages workloads across namespaces has a highly privileged SA. Today those privileges are static, permanent, and exploitable."
- State the solution in one sentence: "operator-security-runtime provides 4 packages — each targeting a different attack vector — that you can adopt incrementally."
- Walk through the key numbers. Pause on: "1 kubectl command is all it takes" and "0 cluster-wide permissions when no CR is active."
- Mention library status briefly — don't linger, you'll cover details later.

**Transition**: "These numbers aren't theoretical. Let me show you the CVE history."

---

## Slide 3: CVE Timeline (3 min)

**Key message**: SA abuse is a real, accelerating threat — not a theoretical risk.

**Talking points**:
- Start at 2015: "The Kubernetes community flagged SA authorization as a design concern in issue 17637. The use verb concept was introduced for PodSecurityPolicy, but PodSecurityPolicy was removed in 1.25 — leaving no SA usage restriction."
- Move through the timeline: "By 2021, CVE-2021-25740 exposed cross-namespace endpoint access. In 2023, GCP-2023-047 showed real-world overprivileged SA abuse in managed Kubernetes — different vector from aggregate-to-edit, but the same root cause of SA overprovisioning."
- Land on 2024-2025: "CVE-2024-43403 is the one that matters most for us — Kanister operator SA token exposure via aggregate-to-edit. This is the exact escalation path our library addresses. Then IngressNightmare: CVE-2025-1974, CVSS 9.8. Different vector — admission controller RCE — but same outcome: overprivileged operator SA leads to full cluster takeover."
- Key point: "Two takeaways: the escalation paths are real, and the impact of an overprivileged SA is catastrophic regardless of how it's compromised."

**Transition**: "Let me show you exactly how this attack works against our operators."

---

## Slide 4: The Attack (5 min) — MOST IMPORTANT SLIDE

**Key message**: A namespace editor can impersonate the operator SA with one command, and the API server resolves this BEFORE webhooks see it.

**Talking points**:
- Walk through the left zone: "aggregate-to-edit ships with every cluster. It carries our operator's verbs — including impersonate — and merges them into the edit role. Every namespace editor inherits this."
- Walk through the right zone: "One command. `kubectl --as=system:serviceaccount:ns:operator-sa get secrets -A`. That's it."
- Explain the critical insight: "The API server resolves impersonation at the authentication layer — BEFORE admission webhooks run. Webhooks see the impersonated identity as the requesting user. Note that Kubernetes audit logs DO capture the original user via Impersonate-User headers — so impersonation is logged. But at admission time, the webhook can't tell the difference. That's why we strip the verb proactively."
- Show the defense points: "impersonationguard blocks at the ClusterRole level — it patches `system:aggregate-to-edit` to remove the impersonate verb before any user inherits it. saprotection blocks pod-based SA hijacking. Together they cover both vectors. See Slide 7 for the full package breakdown."
- Emphasize: "This is not hypothetical. We've verified this against our operator in [environment]."

**Transition**: "Now let me show you what an attacker can do once they bypass protection."

---

## Slide 5: Impact (2 min)

**Key message**: The blast radius is the entire cluster, and these actions are indistinguishable from normal operator activity.

**Talking points**:
- Walk the table quickly — don't read every row, highlight the worst: "Read all secrets. Escalate to cluster-admin if the SA holds escalate. Persist access by creating new bindings."
- Hit the detection gap: "Audit logs DO capture impersonation — so that vector is logged. But when an attacker has a raw SA token from a volume mount or the token API, there's no way to distinguish their requests from legitimate operator activity. Every action looks normal."
- Quantify: "For ODH, this means [N] namespaces, [N] secrets."

**Transition**: "So what do we protect against, and what's explicitly out of scope?"

---

## Slide 6: Threat Model (3 min)

**Key message**: We protect against 4 RBAC-level attack vectors. We explicitly do NOT try to solve infrastructure-level attacks.

**Talking points**:
- Walk the left side: "Four attack surfaces: pod SA hijacking, SA impersonation, token minting, and overprivileged SA exposure."
- Walk the middle: "Each maps to a specific package. Notice the verb differences: saprotection and impersonationguard BLOCK — preventive controls. rbacscope LIMITS BLAST RADIUS — scope reduction. rbacaudit DETECTS — detective control."
- Walk the right side confidently: "Out of scope: etcd, container escape, network, supply chain, API server compromise. These are infrastructure concerns with dedicated tooling — Falco, Sigstore, Cilium. We integrate via structured logs; we don't replace them."
- Key phrase: "A credible security design defines its boundaries."

**Transition**: "Let me walk you through how each package works."

---

## Slide 7: Defense-in-Depth (3 min)

**Key message**: 4 packages, each independently adoptable, each with a defined failure mode.

**Talking points**:
- Walk each branch of the mindmap. Don't read the details — summarize:
  - "saprotection: webhook on pod create AND update. If it's down, failurePolicy Fail blocks creates in watched namespaces."
  - "impersonationguard: continuously reconciles system:aggregate-to-edit via a controller-runtime watch. It also sets `autoupdate=false` on the ClusterRole — this prevents the Kubernetes RBAC controller from re-adding the impersonate verb on API server restarts. If someone reverts it — even during a cluster upgrade — the operator re-patches within seconds."
  - "rbacscope: imperative model — the caller's reconciler calls EnsureAccess and CleanupAccess as utility functions. No watches, no informers, no additional API server load for RBAC resources. This is different from impersonationguard, which runs its own watch loop — and that's intentional. RBAC resources are tied to CR lifecycle, so they only need updating when the CR is reconciled. If a team wants immediate drift recovery, they add Owns(Role) and Owns(RoleBinding) in SetupWithManager — standard controller-runtime, nothing custom."
  - "rbacscope also has dual ownership — OwnerReferences same-namespace, annotations cross-namespace. GarbageCollectOrphanedOwners recovers from crashes. Default denied namespaces protect kube-system and openshift-*."
  - "rbacaudit: startup scan of ClusterRoles AND namespace Roles for impersonate and token-create exposure. Returns structured findings. If it fails, detection degrades but availability is unaffected."
- Emphasize independence: "You can start with rbacaudit alone — zero risk — and add others incrementally."

**Transition**: "Now let me show you the net effect on the RBAC model."

---

## Slide 8: Before vs After (3 min)

**Key message**: From permanent cluster-wide access to ephemeral namespace-scoped access tied to CR lifecycle.

**Talking points**:
- Point to the STATIC column: "Today, the operator has access to every namespace — including 'unrelated.' That red arrow is the problem. Unnecessary access, always on."
- Point to DYNAMIC ACTIVE: "With rbacscope, permissions exist only where CRs are deployed. 'Unrelated' gets nothing."
- Point to DYNAMIC DELETED: "When the CR is deleted, permissions are cleaned up. Zero residual access."
- Walk the comparison table. Pause on: "Audit trigger: None → CR create/delete events."
- Mention coexistence: "During migration, both models run simultaneously. The static binding stays until you validate the dynamic model."
- Performance note: "One thing to highlight — rbacscope adds these Roles and RoleBindings imperatively during reconciliation. It doesn't set up watch streams or informer caches for them. So the overhead is exactly what you see: 1 Role + 1 RoleBinding per namespace, created or updated during the normal reconcile cycle. Zero background processes."

**Transition**: "This brings us to the question I know you're thinking — what about the escalate verb?"

---

## Slide 9: The escalate Trade-off (4 min)

**Key message**: The escalate path is safer than static ClusterRoles in every measurable dimension.

**Talking points**:
- Acknowledge the concern directly: "I know what you're thinking. Escalate sounds dangerous. Let me walk through the comparison."
- Walk the table row by row. Let the visual do the work — red full-width bars vs short green bars.
- Clarify what escalate is: "Important distinction: the library code itself does not reference or exercise the escalate verb. It uses standard controllerutil.CreateOrUpdate calls. The escalate verb is a deployment-time prerequisite — the operator's ClusterRole manifest must grant it so that Kubernetes allows creating Roles that grant permissions the SA doesn't already hold."
- Key argument: "To abuse escalate, an attacker needs a valid operator SA token — via binary compromise, volume mount, or node-level theft. But every one of those vectors ALSO compromises a static ClusterRole. And with the static model, the damage is permanent and cluster-wide. With rbacscope, it's scoped and ephemeral."
- Be honest about the trade-off: "I want to be transparent: escalate introduces a new escalation primitive. Within a namespace, it permits arbitrary Role creation. This is a real but bounded risk — bounded because it's namespace-scoped, not cluster-scoped. The SA never has escalate on ClusterRoles. You can verify this in the ClusterRole manifest."
- Close: "The escalate path provides stronger security properties in most measurable dimensions, with a small, bounded complexity trade-off."

**Transition**: "You might also wonder: why not just use Gatekeeper or Kyverno?"

---

## Slide 10: Why Not Existing Tools? (2 min)

**Key message**: Policy engines can't do CR-lifecycle-aware dynamic RBAC. That's the gap this library fills.

**Talking points**:
- "Gatekeeper and Kyverno are excellent for cluster-wide policy. If you're using them, keep using them."
- "But they can't tie RBAC to CR lifecycle — create a RoleBinding when a CR appears, delete it when the CR is removed. That requires reconciler-level integration."
- "And impersonationguard patches a ClusterRole at startup. That's not expressible as an admission policy."
- "These tools complement each other. This is not a replacement proposal."

**Transition**: "Now let me address operational concerns. Security controls must not break availability."

---

## Slide 11: Webhook HA (2 min)

**Key message**: The webhook is production-grade: 3 replicas, fail-secure, 1-5ms latency, fully monitored.

**Talking points**:
- Hit the highlights from the table: "3 replicas minimum, pod anti-affinity, PDB of 2."
- Namespace exclusion: "kube-system, openshift-*, and the operator namespace are excluded. No deadlock possible."
- failurePolicy: "We use Fail — fail-secure. If the webhook is down, pod creation blocks. We never fail open."
- Latency: "1-5ms p99. String comparison, no external calls, no cache dependencies."
- TLS: "Default cert-manager, with OLM injection as an alternative on OpenShift."

**Transition**: "And if everything goes wrong — here's the escape hatch."

---

## Slide 12: Break-Glass Recovery (2 min)

**Key message**: There is a documented, auditable escape hatch. Recovery takes seconds.

**Talking points**:
- Walk the flowchart top to bottom: "Alert fires. SRE investigates. Most cases self-heal — pods restart in under 30 seconds."
- "If persistent: one command — `kubectl delete vwc operator-sa-guard`. Immediate effect. Pods create normally."
- "Then fix the root cause, redeploy. The reconciler recreates the VWC automatically."
- Access control: "Only cluster-admin or the SRE break-glass role can delete the VWC. Namespace editors can't touch it."
- "Every step is auditable. The deletion, the gap, the restoration — all in K8s audit logs."

**Transition**: "Let me cover testing and compatibility."

---

## Slide 13: Testing and Quality (2 min)

**Key message**: Unit, integration, e2e, and chaos tested. Compatible with K8s 1.27+ and OpenShift 4.14+.

**Talking points**:
- Walk the test levels briefly — don't read the table, summarize: "Unit tests, envtest integration, full e2e on [Kind/OpenShift], and chaos testing of webhook failure under load."
- Race conditions: "Owner references handle cleanup. RoleBinding creation is idempotent. Concurrent CRs converge to correct state."
- Compatibility: "Tested K8s 1.27 through 1.34, OpenShift 4.14 through 4.17."
- OpenShift specifics: "Works with OLM — creates supplementary RoleBindings without touching CSV-managed resources. Runs under restricted SCC."

**Transition**: "Here's the adoption path."

---

## Slide 14: Adoption Path (2 min)

**Key message**: Incremental, reversible, 1-2 days per operator.

**Talking points**:
- Walk the phases: "Phase 0: approve as recommended. Phase 1: rbacaudit — read-only, zero risk, 1 sprint bake. Phase 2: saprotection — webhook. Phase 3: impersonationguard — patches aggregate-to-edit. Phase 4: rbacscope — the RBAC model change."
- Emphasize reversibility: "Every phase has a rollback. Delete the VWC. Revert the CR patch. Reapply the snapshot."
- Code example: "Integration is a single import and config block. This is what it looks like."
- Don't linger on the code — let them read it.

**Transition**: "Let me summarize what we've covered and state the ask."

---

## Slide 15: Summary and Call to Action (3 min)

**Key message**: Approve as recommended, pilot rbacaudit, designate a maintainer.

**Talking points**:
- Walk the summary list quickly — these are reminders, not new information.
- State the ask clearly: "Four things. One: approve as a recommended library. Two: pilot rbacaudit across [2-3 operators] in 2 sprints, results back to this council. Three: fund the rollout — one engineer per adopting team, one quarter. Four: designate [team] as maintainer."
- Maintenance commitment: "SLA of 48h for critical patches. Tested against N-2 K8s releases. Forking plan if maintenance ceases."
- Close with the risk statement: "The risk of inaction is quantifiable: every operator we ship today has a known, exploitable privilege escalation path. For impersonation attacks, audit logs capture the original user. For token-theft attacks, the activity is indistinguishable from legitimate operator behavior."
- Pause. Then: "I'm happy to take questions."

---

## General Presentation Tips

1. **Pace**: ~40 minutes for 15 slides. Slides 4 (attack) and 9 (escalate) are the longest — plan 5 and 4 minutes respectively.
2. **Eye contact**: During the attack chain walkthrough, step through it slowly. Let the audience absorb each step.
3. **Confidence signals**: Use "we" not "I". Say "this is" not "I think this is." Don't hedge with "hopefully" or "I believe."
4. **When challenged**: Thank the questioner, restate the question, then answer directly. If you don't know, say "I'll follow up with the exact number after this session."
5. **The escalate question WILL come**: Be ready for it. Slide 9 is your preparation. Don't get defensive — walk through the comparison table calmly.
6. **Placeholders**: Before presenting, fill ALL `[bracketed]` values with real numbers. Every placeholder undermines credibility.

---

# Anticipated Questions and Answers

## Category 1: Technical Architecture

### Q1: "Does aggregate-to-edit actually grant the impersonate verb in upstream Kubernetes?"

**Answer**: "Yes — the built-in `system:aggregate-to-edit` ClusterRole grants the `impersonate` verb on `serviceaccounts` by default in upstream Kubernetes. This is not specific to our operator — it ships with every cluster. impersonationguard patches this specific built-in ClusterRole to remove the impersonate verb. You can verify with `kubectl get clusterrole system:aggregate-to-edit -o yaml | grep -A5 impersonate`."

**If pressed**: "I can show you the exact ClusterRole and our patch logic after this session."

---

### Q2: "The API server resolves impersonation before webhooks — can't you just check the `Impersonate-User` header?"

**Answer**: "The `Impersonate-User` header is consumed by the API server at the authn layer and stripped before the request reaches admission webhooks. By the time our ValidatingWebhook sees the request, the caller identity has been resolved to the impersonated SA. There's no header to check. That's why impersonationguard strips the verb at the source — preventing impersonation entirely rather than trying to detect it after the fact."

---

### Q3: "What happens if aggregate-to-edit is reconciled by a cluster component and your patch is reverted?"

**Answer**: "impersonationguard runs as a reconciliation loop. If the ClusterRole is modified — by any actor — the operator detects the change and re-applies the patch. The reconciliation is triggered immediately via a Kubernetes watch on the ClusterRole — not on a polling interval. This is the standard Kubernetes controller pattern — eventually consistent."

---

### Q4: "Can the escalate verb be used to create ClusterRoles, not just namespace Roles?"

**Answer**: "No. rbacscope is configured to operate on namespace-scoped Roles and RoleBindings only. The operator's RBAC configuration explicitly does not grant `escalate` on ClusterRoles or ClusterRoleBindings. You can verify this in the ClusterRole manifest."

---

### Q5: "What about the sa/token API? Can an attacker mint tokens even with rbacscope?"

**Answer**: "Yes, within namespaces where the operator has an active CR. rbacscope reduces the blast radius — tokens can only be minted for namespaces with active CRs, not cluster-wide. Full prevention of token minting requires upstream changes. rbacscope provides defense-in-depth by limiting the scope, not eliminating the vector entirely. We classify this as 'blast-radius limited by' rather than 'blocked by' in our threat model — we're honest about the limitation."

---

### Q6: "What happens if saprotection and impersonationguard are both down?"

**Answer**: "saprotection is a ValidatingWebhook with failurePolicy: Fail. If it's down, pod creation blocks in watched namespaces. impersonationguard is a ClusterRole patch — it's not a runtime component. Once applied, the verb is stripped regardless of whether the operator is running. The patch persists until something explicitly reverts it."

---

## Category 2: Operational Concerns

### Q7: "What happens during an operator rolling update? Does pod creation block?"

**Answer**: "No. The PDB ensures at least 2 of 3 replicas remain available during rolling updates. The update proceeds one pod at a time. We've tested this — zero pod creation failures during rolling updates in [environment]."

---

### Q8: "What if someone sets replicas to 1?"

**Answer**: "The library enforces a minimum of 2 replicas. If someone manually scales down to 1 via kubectl, the PDB will still prevent eviction below quorum, but a crash of that single pod would cause pod creation to block. This is by design — fail-secure."

---

### Q9: "What's the performance impact at scale — say 1000 pods/minute?"

**Answer**: "At 1000 pods/minute, that's ~17 requests per second across 3 replicas — roughly 6 per replica. At 1-5ms per request, each replica has capacity for thousands of requests per second. We're orders of magnitude below the throughput ceiling. The webhook does a string comparison — no external calls, no database lookups, no cache."

**If pressed for benchmarks**: "I can share the detailed benchmark data — P50, P99, P99.9 at various load levels — after this session."

---

### Q10: "Who manages the TLS certificates for the webhook?"

**Answer**: "Default is cert-manager with automatic rotation. On OpenShift, we can use OLM CA injection instead. Self-signed with 90-day auto-rotation is a third option. All three are tested. No manual certificate management is required."

---

### Q11: "What if the operator itself is crash-looping and the webhook is down?"

**Answer**: "The break-glass procedure applies. Delete the VWC — pod creation resumes immediately. Fix the root cause, redeploy. The reconciler recreates the VWC. During the gap, K8s audit logs capture all SA activity for post-incident review. The VWC deletion itself is auditable."

---

## Category 3: Alternatives and Strategy

### Q12: "Why not just use Gatekeeper? It can block pod SA assignment."

**Answer**: "Gatekeeper can do what saprotection does — block pods from using specific SAs. But it cannot do what rbacscope does — dynamically create and delete RoleBindings tied to CR lifecycle. It also cannot do what impersonationguard does — patch a ClusterRole at startup. These are reconciler-level operations that require Go library integration. Gatekeeper is great for cluster-wide policy — we recommend using it alongside this library, not instead of it."

---

### Q13: "Can't we just wait for KEP-5284?"

**Answer**: "KEP-5284 (Constrained Impersonation) introduces verb-scoped impersonation restrictions and reached alpha targeting K8s 1.34-1.35. It addresses impersonation privilege at the authorization layer — which overlaps with what impersonationguard does. But it does not address dynamic RBAC scoping, token minting blast radius, or operator-specific RBAC audit. Even when KEP-5284 graduates to GA, we'll still need rbacscope and rbacaudit. And GA is likely 2+ years away — we're exposed today. When KEP-5284 graduates, we retire the impersonationguard package."

---

### Q14: "Who maintains this library? What's the bus factor?"

**Answer**: "[Team name] maintains it. [N] engineers have merge permissions and deep knowledge. Security patch SLA is 48 hours for critical severity. The library is under [N] KLOC — small enough that any team can fork and absorb it if maintenance ceases. We follow semver with a 1-release deprecation cycle."

---

### Q15: "What's the cost of adoption? How many person-weeks?"

**Answer**: "1-2 days per operator for the full stack. Phase 1 alone — rbacaudit — is a single import and zero configuration. It runs at startup, scans RBAC, and logs findings. No mutations, no webhooks. The pilot will give us exact numbers for the more complex phases."

---

## Category 4: Political / Decision

### Q16: "Why are you asking for 'recommended' rather than 'mandatory'?"

**Answer**: "Because we believe in data-driven decisions. The pilot with rbacaudit will produce concrete findings — which operators are exposed, how severe the gaps are. Those findings, presented back to this council, will inform whether mandatory adoption is warranted. We're asking you to approve the tool and the pilot, not a mandate."

---

### Q17: "What if the pilot finds no significant exposure?"

**Answer**: "Then we have evidence that our RBAC posture is stronger than we assumed — which is still valuable. But based on the CVE trend and the design of aggregate-to-edit, I would be surprised if rbacaudit finds zero issues. Either way, the council will have data to make an informed decision."

---

### Q18: "What happens to this library if Kubernetes upstream solves this problem?"

**Answer**: "We have explicit deprecation criteria. If upstream provides: (1) constrained impersonation via KEP-5284 GA — we retire impersonationguard. (2) use verb enforcement for SA token mounting — saprotection becomes optional. (3) Native dynamic RBAC scoping tied to resource lifecycle — we retire rbacscope. (4) Operator-aware RBAC audit — we retire rbacaudit. Each package is retired independently. We monitor KEP status quarterly and report to this council. Until then, we fill gaps that upstream has left open."

---

## Category 5: Architecture and Strategy

### Q19: "Why should this be a library and not a standalone controller?"

**Answer**: "A centralized controller would mean one team maintains it — simpler operationally. But it introduces a hard runtime dependency, version coupling, and a single point of failure for all operators. A library approach means each operator team controls their upgrade cadence, can adopt packages incrementally, and has no external runtime dependency beyond their own binary. The trade-off is that N teams must independently upgrade — we mitigate this with semver, a 1-release deprecation cycle, and automated dependency update tooling. We chose the library model because operator teams need control over their own security posture and upgrade timing."

---

### Q20: "What is your threat model for the webhook itself? Aren't you introducing a new privileged component?"

**Answer**: "Yes, the webhook is a new component and we've threat-modeled it. Its SA requires only get/list on Pods and ServiceAccounts — no write permissions, no secrets access, no escalate/bind/impersonate verbs. The webhook namespace is excluded from its own validation to prevent deadlock. Compromise of the webhook SA does not grant escalation privileges. The webhook does not make external calls — it performs a string comparison against a static allowlist. The main risk is availability impact from failurePolicy:Fail, which is why we have 3 replicas, PDB, and the break-glass procedure."

---

### Q21: "You claim 1-2 days per operator. Have you actually migrated one?"

**Answer**: "We have validated against [operator name] in [environment]. The integration is a single import and config block in main.go — the code example on Slide 14 is the actual integration, not a simplified version. The 1-2 day estimate includes writing tests and CI updates. For operators with unusual RBAC patterns, the estimate may be higher — the pilot will give us empirical data for the more complex phases."

**If not yet validated**: "We have validated the library's functionality in isolation and against the ODH operator's RBAC model. The pilot phase exists precisely to validate the integration effort estimate empirically before broader rollout."

---

### Q22: "Your CVE timeline shows Kubernetes has been fixing these issues for 10 years. What makes you think they'll stop? What are the kill criteria for this library?"

**Answer**: "We don't assume upstream will stop. We have explicit deprecation criteria: if upstream Kubernetes provides (1) constrained impersonation via KEP-5284 GA, (2) use verb enforcement for SA token mounting, (3) native dynamic RBAC scoping tied to resource lifecycle, AND (4) operator-aware RBAC audit — we deprecate the corresponding packages. Each package can be retired independently. But note that even KEP-5284 — the most mature upstream effort — only addresses impersonation. Dynamic RBAC scoping is not on any upstream roadmap. We monitor KEP status quarterly."

---

### Q23: "How many actual incidents have we had? Is this solving a real problem or a theoretical one?"

**Answer**: "To my knowledge, we have not had a confirmed SA abuse incident internally. However, CVE-2024-43403 demonstrates this exact attack path against a real operator (Kanister). CVE-2025-1974 showed the impact with 6500+ clusters exposed at disclosure. The question is not whether this attack path exists — it demonstrably does — but whether we want to be proactive or reactive. rbacaudit as a Phase 1 pilot costs us nothing and will produce concrete data on our actual exposure. That data, not theoretical risk, will drive the decision on Phases 2-4."

---

### Q24: "Can an attacker create a CR in a target namespace to trigger rbacscope RoleBinding creation, then exploit the resulting permissions?"

**Answer**: "CR creation requires permissions on the operator's CRD — this is not something a namespace editor gets by default. Even if they could create a CR, the resulting RoleBinding grants permissions to the operator's SA, not to the attacker. To exploit those permissions, the attacker would still need to obtain a valid token for the operator SA — which brings us back to the token theft vector that rbacscope limits by scoping permissions to only CR namespaces."

---

### Q25: "What happens during a Kubernetes version upgrade? Does the upgrade re-create the original aggregate-to-edit ClusterRole and undo the impersonationguard patch?"

**Answer**: "Yes, a cluster upgrade may re-create or modify the aggregate-to-edit ClusterRole. impersonationguard has two defenses against this: first, it sets the `rbac.authorization.kubernetes.io/autoupdate: false` annotation on the ClusterRole, which tells the Kubernetes RBAC controller not to auto-reconcile it back to its default state on API server restart. Second, it runs a reconciliation loop with a watch — if the ClusterRole is modified by any actor despite the annotation, the operator re-applies the patch within seconds. There is a brief window during the upgrade, but saprotection's webhook is still active and blocks pod-based SA hijacking independently."

---

### Q26: "You said rbacscope creates namespace-scoped Roles, but the library has ClusterRBACScoper. Doesn't that undermine the security argument?"

**Answer**: "The library provides two scopers. `RBACScoper` manages namespace-scoped Roles and RoleBindings — this is the default and recommended path. `ClusterRBACScoper` exists for operators that genuinely need cluster-wide access to specific resources like nodes or namespaces. The key difference from today's static model is lifecycle management: even cluster-scoped resources are tied to CR lifecycle and cleaned up on deletion. The escalate trade-off analysis on Slide 9 applies to `RBACScoper`. Operators using `ClusterRBACScoper` should evaluate the broader blast radius separately — we recommend it only when namespace-scoped access is genuinely insufficient."

---

### Q27: "What happens when multiple CRs exist in the same namespace?"

**Answer**: "rbacscope handles this with multi-owner support. Each CR is added as an OwnerReference on the shared Role and RoleBinding. When one CR is deleted, only its OwnerReference is removed. The Role and RoleBinding are only deleted when the LAST OwnerReference is removed — so cleanup of one CR never breaks others sharing the same namespace. For cross-namespace grants, the same logic applies via annotation-based ownership."

---

### Q28: "What happens if someone tampers with the ownership annotation on a managed Role?"

**Answer**: "This is a known limitation documented in the code. Any user with update access to Roles or ClusterRoles can modify the annotation — adding fake owners to prevent cleanup, or removing owners to trigger premature deletion. This is mitigated by two factors: managed resources use operator-specific names that other controllers are unlikely to modify, and modifying RBAC resources already requires elevated privileges. For stricter protection, a ValidatingWebhook can restrict annotation modifications to the operator's ServiceAccount. The GarbageCollectOrphanedOwners function also cleans up stale entries by resolving each owner against the API server."

---

### Q29: "Is there a scaling limit on how many CRs can reference the same managed resource?"

**Answer**: "Yes — the annotation-based ownership is capped at 100 entries per resource. This covers the cross-namespace ownership case. Same-namespace CRs use native Kubernetes OwnerReferences, which have no practical limit. For most operators, 100 cross-namespace owners per resource is more than sufficient."

---

### Q30: "rbacscope creates RBAC resources but doesn't watch them. What if someone deletes a managed Role between reconciles?"

**Answer**: "The Role is recreated on the next reconcile — EnsureAccess uses controllerutil.CreateOrUpdate, which is idempotent. The gap between deletion and re-creation is bounded by the reconcile interval. For most operators that's seconds to minutes. If that's too long, the caller adds Owns(&rbacv1.Role{}) in SetupWithManager — controller-runtime then watches those resources and triggers an immediate re-reconcile on deletion. This is a standard pattern; the library doesn't force it because zero-overhead is the better default for most teams."

**If pressed on the gap**: "During the gap, the operator SA loses scoped access in that namespace. It cannot access resources there until the Role is recreated. This is a brief degradation of the operator's functionality, not a security exposure — it's a denial of service to the operator, not an escalation."

---

## Pre-Presentation Checklist

Before presenting, fill in ALL bracketed placeholders:
- [x] `[REPO URL]` — https://github.com/ugiordan/operator-security-runtime ✅
- [x] `[alpha/beta]` — alpha ✅
- [x] `[N%]` — ~90% avg ✅
- [x] `[N] KLOC` — ~2.1 KLOC ✅
- [ ] `[environment]` — where PoC was validated (used in slides AND Q21)
- [ ] `[date]` — when attack was demonstrated
- [ ] `[N] namespaces and [N] secrets` — blast radius numbers for ODH
- [ ] `[N] operators with [N] overprivileged SAs` — risk quantification for Slide 15
- [ ] `[operator-1, operator-2, operator-3]` — pilot operator names
- [ ] `[team]` / `[Name]` — maintaining team name and author
- [ ] `[N]` — number of engineers with merge permissions
- [ ] `[operator name]` in Q21 — which operator was validated
- [ ] `[Kind/OpenShift]` — E2E test platform
- [ ] `[location]` — runbook publication location
- [ ] Verify KEP-5284 status is current at presentation time (check if alpha landed in 1.34 or 1.35)
- [ ] Verify CVE-2024-43403 CVSS score is still 8.8 at presentation time
