#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# MCP AuthZ Demo — Bootstrap Script
# Deploys the full stack on a local kind cluster:
#   1. kind cluster
#   2. Kyverno (admission webhook)
#   3. MCPToolInvocation CRD
#   4. Tenant namespaces + agent ServiceAccounts + RBAC
#   5. Kyverno ClusterPolicies (x4)
#   6. kubernetes-mcp-server via Helm (per tenant)
#   7. AuthZ proxy sidecar (Kyverno enforcement bridge)
#   8. Demo dashboard (Flask)
#
# Prerequisites: kind, kubectl, helm, docker, python3
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

CLUSTER_NAME="mcp-authz-demo"
KYVERNO_VERSION="3.8.1"
K8S_MCP_CHART="oci://ghcr.io/containers/kubernetes-mcp-server/charts/kubernetes-mcp-server"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   MCP AuthZ Demo — Full Stack Bootstrap                  ║"
echo "║   kubernetes-mcp-server + Kyverno AuthZ                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: kind cluster ──────────────────────────────────────────────────────
echo "▶ Step 1: Creating kind cluster '${CLUSTER_NAME}'..."
if sudo kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
   echo "  ✓ Cluster already exists"
else
  sudo kind create cluster --name "${CLUSTER_NAME}" --wait 60s
  echo "  ✓ Cluster created"
fi
# kubectl config use-context "kind-${CLUSTER_NAME}" > /dev/null

# ── Step 2: Kyverno ──────────────────────────────────────────────────────────
echo ""
echo "▶ Step 2: Installing Kyverno ${KYVERNO_VERSION}..."
sudo helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update > /dev/null 2>&1
sudo helm repo update > /dev/null 2>&1

if sudo helm list -n kyverno 2>/dev/null | grep -q kyverno; then
  echo "  ✓ Kyverno already installed"
else
  sudo helm install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace \
    --version "${KYVERNO_VERSION}" \
    --set admissionController.replicas=1 \
    --wait --timeout 120s
  echo "  ✓ Kyverno installed"
fi

# ── Step 3: CRD ──────────────────────────────────────────────────────────────
echo ""
echo "▶ Step 3: Applying MCPToolInvocation CRD..."
sudo kubectl apply -f k8s/crds/mcptoolinvocation-crd.yaml
echo "  ✓ MCPToolInvocation CRD ready"

# ── Step 4: Namespaces + RBAC ─────────────────────────────────────────────────
echo ""
echo "▶ Step 4: Creating tenant namespaces and agent ServiceAccounts..."
sudo kubectl apply -f k8s/rbac/namespaces-and-rbac.yaml
echo "  ✓ tenant-acme, tenant-globex namespaces created"
echo "  ✓ sre-agent, cost-agent, remediation-agent ServiceAccounts created"

# ── Step 5: Kyverno ClusterPolicies ──────────────────────────────────────────
echo ""
echo "▶ Step 5: Applying Kyverno ClusterPolicies..."
sudo kubectl apply -f k8s/policies/01-tool-allowlist.yaml
sudo kubectl apply -f k8s/policies/02-tenant-isolation.yaml
sudo kubectl apply -f k8s/policies/03-human-identity.yaml

echo "  Waiting for policies to become ready..."
sleep 5
sudo kubectl get clusterpolicies
echo "  ✓ All 4 ClusterPolicies applied"

# ── Step 6: kubernetes-mcp-server and AuthZ proxy (per tenant) ──────────────────────
echo ""
echo "▶ Step 6: Building and loading AuthZ proxy image..."
sudo docker build -t mcp-authz-proxy:demo ./mcp_server/
echo "  ✓ Image built: mcp-authz-proxy:demo"
sudo kind load docker-image mcp-authz-proxy:demo --name "${CLUSTER_NAME}"
echo "  ✓ Image loaded into kind (imagePullPolicy: Never)"
echo ""
echo "▶ Step 7: Deploying kubernetes-mcp-server..."
echo "  ✓ kubernetes-mcp-server deployed (tenant-acme + tenant-globex)"
sudo kubectl apply -f k8s/mcp-server/mcp-server-deployment.yaml
echo "  ✓ MCP server + AuthZ proxy sidecar deployed"

# ── Step 8: Python deps ───────────────────────────────────────────────────────
echo ""
echo "▶ Step 8: Installing Python dependencies..."
sudo pip3 install -r requirements.txt --break-system-packages
echo "  ✓ Dependencies installed"

# ── Port-forward helper ───────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅ Demo stack ready!                                   ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  Run the demo dashboard:                                 ║"
echo "║    python3 app.py                                         ║"
echo "║    open http://localhost:5000                            ║"
echo "║                                                          ║"
echo "║  Port-forward MCP AuthZ proxy (for agent_client.py):    ║"
echo "║  sudo kubectl port-forward -n tenant-acme svc/mcp-server \  ║"
echo "║  8090:8090                                           ║"
echo "║                                                          ║"
echo "║  Run the demo agent:                                     ║"
echo "║    python3 agent/agent_client.py                          ║"
echo "║                                                          ║"
echo "║  Watch policy events live:                               ║"
echo "║    kubectl get events -A --field-selector reason=PolicyV ║"
echo "║    kubectl get mcptoolinvocations -A                     ║"
echo "║                                                          ║"
echo "║  Direct kubectl test (dry-run through Kyverno):          ║"
echo "║    kubectl apply -f k8s/agents/demo-invocations.yaml \   ║"
echo "║      --dry-run=server                                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
