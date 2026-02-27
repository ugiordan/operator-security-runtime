# Scenario Simulation

This directory contains files to demonstrate the ServiceAccount isolation gap and how the webhook addresses it.

## Problem Statement

Users with the `edit` ClusterRole in a namespace can create pods referencing ANY ServiceAccount name in the pod spec. When that ServiceAccount exists in the namespace, the pod runs with its mounted token and all associated RBAC permissions. This is a gap in the standard Kubernetes RBAC model that allows:

1. **Privilege escalation** - User gains the RBAC permissions bound to the referenced ServiceAccount
2. **Secret access** - Operator ServiceAccounts often have cluster-wide secrets access via ClusterRoleBindings
3. **Impersonation** - Actions performed by the pod appear to originate from the operator's identity

In real-world scenarios, the operator's ServiceAccount may exist in user namespaces because:
- The operator deploys components (e.g., model servers, notebooks) into those namespaces
- The operator creates its SA in watched namespaces for reconciliation purposes
- A user with `edit` permissions can create a ServiceAccount with the same name

## Scenario Files

- `user-namespace.yaml` - Creates a namespace with a user that has standard `edit` role, plus a ServiceAccount matching the operator's SA name (simulating a realistic deployment where the SA exists)
- `exploit.yaml` - Pod that references the operator's ServiceAccount name, gaining its RBAC permissions
- `test-attack.sh` - Automated script to test both scenarios (with and without protection)

## Manual Steps

### 1. Without Webhook Protection

```bash
# Deploy operator without webhook
make deploy IMG=controller:latest
kubectl set env deployment/k8s-serviceaccount-hijacking-protection-controller-manager \
  -n k8s-serviceaccount-hijacking-protection-system ENABLE_WEBHOOKS=false

# Create user namespace
kubectl apply -f attack/user-namespace.yaml

# Create pod with operator SA (succeeds - no protection)
kubectl apply -f attack/exploit.yaml

# Observe the pod runs with operator privileges
kubectl logs -n user-project malicious-pod
```

### 2. With Webhook Protection

```bash
# Deploy operator with webhook
make deploy IMG=controller:latest

# Attempt to create pod with operator SA (denied by webhook)
kubectl apply -f attack/exploit.yaml
# Expected: Error from server (Forbidden): admission webhook denied the request

# Verify webhook is active
kubectl get validatingwebhookconfigurations
```

## Automated Testing

```bash
./attack/test-attack.sh
```

This script:
1. Deploys operator with webhook
2. Attempts scenario (should fail)
3. Disables webhook
4. Attempts scenario (should succeed - demonstrates the gap)
5. Re-enables webhook
6. Verifies protection restored
