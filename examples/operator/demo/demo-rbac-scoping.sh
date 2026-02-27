#!/usr/bin/env bash
#
# demo-rbac-scoping.sh
#
# Demonstrates the dynamic RBAC scoping lifecycle:
#   - Operator's ClusterRole has NO secrets permissions
#   - When a CR is created in a namespace, a scoped Role/RoleBinding is created
#     granting the operator secrets access in that namespace only
#   - When the CR is deleted, the scoped Role/RoleBinding is cleaned up
#
# Usage:
#   OPERATOR_NAME=example-operator ./demo-rbac-scoping.sh
#
# Prerequisites:
#   - A running Kubernetes cluster (Kind recommended)
#   - The operator is deployed (make deploy IMG=...)
#   - kubectl configured to talk to the cluster

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OPERATOR_NAME="${OPERATOR_NAME:-example-operator}"
ROLE_NAME="${OPERATOR_NAME}-scoped-access"
ROLEBINDING_NAME="${OPERATOR_NAME}-scoped-access-binding"
CLUSTERROLE_NAME="k8s-serviceaccount-hijacking-protection-manager-role"
RECONCILE_WAIT=3   # seconds to wait for reconciliation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
step() { echo -e "\n${YELLOW}==> $*${NC}"; }

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    step "Cleaning up demo resources..."
    kubectl delete -f "${SCRIPT_DIR}/cr-project-b.yaml" --ignore-not-found=true 2>/dev/null || true
    kubectl delete -f "${SCRIPT_DIR}/cr-project-a.yaml" --ignore-not-found=true 2>/dev/null || true
    # Wait briefly for finalizers to run before deleting namespaces
    sleep 2
    kubectl delete namespace project-a --ignore-not-found=true 2>/dev/null || true
    kubectl delete namespace project-b --ignore-not-found=true 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete.${NC}"
}
trap cleanup EXIT

# ===========================================================================
# Step 1: Verify operator ClusterRole has NO secrets permissions
# ===========================================================================
step "Step 1: Verify operator ClusterRole has NO secrets permissions"

if kubectl get clusterrole "${CLUSTERROLE_NAME}" -o yaml | grep -q '"secrets"'; then
    fail "ClusterRole ${CLUSTERROLE_NAME} contains secrets permissions -- expected none"
fi
pass "ClusterRole ${CLUSTERROLE_NAME} does NOT grant secrets access"

# ===========================================================================
# Step 2: Create test namespaces with secrets
# ===========================================================================
step "Step 2: Create test namespaces and secrets"

kubectl apply -f "${SCRIPT_DIR}/namespaces.yaml"
pass "Namespaces project-a and project-b created with test secrets"

# ===========================================================================
# Step 3: Verify no scoped Roles exist yet
# ===========================================================================
step "Step 3: Verify no scoped Roles exist yet"

if kubectl get role "${ROLE_NAME}" -n project-a 2>/dev/null; then
    fail "Role ${ROLE_NAME} already exists in project-a before any CR was created"
fi
pass "No scoped Role in project-a"

if kubectl get role "${ROLE_NAME}" -n project-b 2>/dev/null; then
    fail "Role ${ROLE_NAME} already exists in project-b before any CR was created"
fi
pass "No scoped Role in project-b"

# ===========================================================================
# Step 4: Deploy CR in project-a -- expect scoped Role to be created
# ===========================================================================
step "Step 4: Deploy ExampleResource CR in project-a"

kubectl apply -f "${SCRIPT_DIR}/cr-project-a.yaml"
echo "Waiting ${RECONCILE_WAIT}s for reconciliation..."
sleep "${RECONCILE_WAIT}"

if ! kubectl get role "${ROLE_NAME}" -n project-a &>/dev/null; then
    fail "Role ${ROLE_NAME} was NOT created in project-a after deploying CR"
fi
pass "Scoped Role ${ROLE_NAME} created in project-a"

# ===========================================================================
# Step 5: Show the Role and RoleBinding in project-a
# ===========================================================================
step "Step 5: Inspect scoped Role and RoleBinding in project-a"

echo ""
echo -e "${YELLOW}--- Role ---${NC}"
kubectl get role "${ROLE_NAME}" -n project-a -o yaml

echo ""
echo -e "${YELLOW}--- RoleBinding ---${NC}"
kubectl get rolebinding "${ROLEBINDING_NAME}" -n project-a -o yaml

pass "Role and RoleBinding present in project-a"

# ===========================================================================
# Step 6: Verify NO scoped Role in project-b (no CR there yet)
# ===========================================================================
step "Step 6: Verify NO scoped Role in project-b (no CR deployed there)"

if kubectl get role "${ROLE_NAME}" -n project-b 2>/dev/null; then
    fail "Role ${ROLE_NAME} unexpectedly exists in project-b"
fi
pass "No scoped Role in project-b (as expected)"

# ===========================================================================
# Step 7: Deploy CR in project-b -- expect scoped Role to be created
# ===========================================================================
step "Step 7: Deploy ExampleResource CR in project-b"

kubectl apply -f "${SCRIPT_DIR}/cr-project-b.yaml"
echo "Waiting ${RECONCILE_WAIT}s for reconciliation..."
sleep "${RECONCILE_WAIT}"

if ! kubectl get role "${ROLE_NAME}" -n project-b &>/dev/null; then
    fail "Role ${ROLE_NAME} was NOT created in project-b after deploying CR"
fi
pass "Scoped Role ${ROLE_NAME} created in project-b"

# ===========================================================================
# Step 8: Delete CR from project-a -- expect Role to be cleaned up
# ===========================================================================
step "Step 8: Delete CR from project-a -- verify scoped Role is cleaned up"

kubectl delete -f "${SCRIPT_DIR}/cr-project-a.yaml"
echo "Waiting ${RECONCILE_WAIT}s for cleanup..."
sleep "${RECONCILE_WAIT}"

if kubectl get role "${ROLE_NAME}" -n project-a &>/dev/null; then
    fail "Role ${ROLE_NAME} still exists in project-a after CR deletion"
fi
pass "Scoped Role cleaned up from project-a after CR deletion"

# ===========================================================================
# Step 9: Verify Role still exists in project-b
# ===========================================================================
step "Step 9: Verify scoped Role still exists in project-b"

if ! kubectl get role "${ROLE_NAME}" -n project-b &>/dev/null; then
    fail "Role ${ROLE_NAME} was unexpectedly removed from project-b"
fi
pass "Scoped Role still present in project-b (CR still exists there)"

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  All checks passed! Demo complete.${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Key takeaways:"
echo "  1. The operator ClusterRole has NO secrets permissions."
echo "  2. Scoped Roles are created dynamically when CRs are deployed."
echo "  3. Each namespace gets its own Role/RoleBinding (least-privilege)."
echo "  4. Removing a CR cleans up the scoped RBAC in that namespace."
echo "  5. Other namespaces with active CRs are unaffected."
