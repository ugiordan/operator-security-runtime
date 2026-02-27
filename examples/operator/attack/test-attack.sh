#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== ServiceAccount Isolation Test ===${NC}"
echo ""

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    kubectl delete -f attack/exploit.yaml --ignore-not-found=true 2>/dev/null || true
    kubectl delete -f attack/user-namespace.yaml --ignore-not-found=true 2>/dev/null || true
}

trap cleanup EXIT

echo -e "${YELLOW}Step 1: Deploy operator with webhook protection${NC}"
make deploy IMG=controller:latest
echo ""

echo -e "${YELLOW}Step 2: Create user namespace${NC}"
kubectl apply -f attack/user-namespace.yaml
echo ""

echo -e "${YELLOW}Step 3: Attempt scenario WITH webhook (should be blocked)${NC}"
if kubectl apply -f attack/exploit.yaml 2>&1 | grep -q "denied the request\|unauthorized"; then
    echo -e "${GREEN}PASS: Webhook blocked the request!${NC}"
    WEBHOOK_BLOCKS=true
else
    echo -e "${RED}FAIL: Request was not blocked!${NC}"
    WEBHOOK_BLOCKS=false
fi
echo ""

# Clean up pod if it was created
kubectl delete pod -n user-project malicious-pod --ignore-not-found=true 2>/dev/null || true

echo -e "${YELLOW}Step 4: Disable webhook${NC}"
kubectl delete validatingwebhookconfigurations \
    k8s-serviceaccount-hijacking-protection-validating-webhook-configuration \
    --ignore-not-found=true
echo ""

echo -e "${YELLOW}Step 5: Attempt scenario WITHOUT webhook (should succeed - demonstrates gap)${NC}"
if kubectl apply -f attack/exploit.yaml; then
    # Wait for pod to be running
    kubectl wait --for=condition=Ready pod/malicious-pod -n user-project --timeout=30s 2>/dev/null || true

    echo -e "${YELLOW}CONFIRMED: Pod created without webhook protection${NC}"
    echo "Pod logs:"
    kubectl logs -n user-project malicious-pod 2>/dev/null || true
    GAP_EXISTS=true
else
    echo -e "${GREEN}Unexpected: Pod creation failed even without webhook${NC}"
    GAP_EXISTS=false
fi
echo ""

echo -e "${YELLOW}Step 6: Re-enable webhook${NC}"
make deploy IMG=controller:latest
echo ""

echo -e "${YELLOW}Step 7: Delete test pod${NC}"
kubectl delete -f attack/exploit.yaml --ignore-not-found=true 2>/dev/null || true
echo ""

echo -e "${YELLOW}Step 8: Verify protection restored${NC}"
if kubectl apply -f attack/exploit.yaml 2>&1 | grep -q "denied the request\|unauthorized"; then
    echo -e "${GREEN}PASS: Webhook blocking after re-enable!${NC}"
    WEBHOOK_BLOCKS_AGAIN=true
else
    echo -e "${RED}FAIL: Request was not blocked after re-enabling!${NC}"
    WEBHOOK_BLOCKS_AGAIN=false
fi
echo ""

echo -e "${YELLOW}=== Test Results ===${NC}"
echo ""
if $WEBHOOK_BLOCKS && $GAP_EXISTS && $WEBHOOK_BLOCKS_AGAIN; then
    echo -e "${GREEN}All tests passed!${NC}"
    echo "1. Webhook blocks request when enabled"
    echo "2. Gap exists when webhook disabled"
    echo "3. Webhook blocks request after re-enable"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    echo "Webhook blocks: $WEBHOOK_BLOCKS"
    echo "Gap exists: $GAP_EXISTS"
    echo "Webhook blocks again: $WEBHOOK_BLOCKS_AGAIN"
    exit 1
fi
