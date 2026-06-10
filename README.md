
## Architecture

```
AI Agent
   │
   │  MCP tools/call  (JSON-RPC over SSE)
   ▼
AuthZ Proxy  :8090           ← agents connect HERE
   │
   │  Creates MCPToolInvocation CR in Kubernetes
   ▼
Kyverno Admission Webhook    ← ClusterPolicies fire here
   │
   ├── DENY  → 403 back to proxy → error to agent
   │
   └── ALLOW → proxy forwards to MCP server
                   │
                   ▼
        kubernetes-mcp-server  :8080  (quay.io/containers/kubernetes_mcp_server)
                   │
                   ▼
        Kubernetes API Server  (real cluster operations)
```

The `kubernetes-mcp-server` is the **real** MCP server from the [containers/](https://github.com/containers/kubernetes-mcp-server) org — a native Go binary that talks directly to the Kubernetes API. It exposes all K8s operations as MCP tools.

The **AuthZ proxy** is a sidecar that sits in front of it. Every tool call creates a `MCPToolInvocation` CR. Kyverno's admission webhook evaluates four ClusterPolicies on that CR. Only admitted calls reach the MCP server.

---

## What the four policies enforce

| Policy | File | What it blocks |
|---|---|---|
| `mcp-tool-allowlist` | `01-tool-allowlist.yaml` | SRE agent calling `pods_delete` — not in its allowlist |
| `mcp-tenant-isolation` | `02-tenant-isolation.yaml` | Agent in `tenant-acme` querying `tenant-globex` resources |
| `mcp-inject-human-identity` | `03-human-identity.yaml` | Mutating: injects `triggered-by` annotation on every call |
| `mcp-require-human-trigger` | `03-human-identity.yaml` | Write tools (`pods_delete`, `deployments_scale`) without a human `triggeredBy` |

---

## Repository structure

```
mcp-authz-demo/
├── app.py                         # Flask demo dashboard (simulated + real mode)
├── requirements.txt
├── dockerfile
├── setup.sh                       # One-command bootstrap
│
├── mcp_server/
│   ├── authz_proxy.py             # ← THE BRIDGE: intercepts tool calls, creates CRs
│   └── Dockerfile                 # Proxy container image
│
├── agent/
│   └── agent_client.py            # Demo agent — connects to proxy, runs 5 scenarios
│
├── templates/ + static/           # Dashboard UI
│
└── k8s/
    ├── crds/
    │   └── mcptoolinvocation-crd.yaml
    ├── rbac/
    │   └── namespaces-and-rbac.yaml     # tenant-acme, tenant-globex, agent SAs
    ├── policies/
    │   ├── 01-tool-allowlist.yaml
    │   ├── 02-tenant-isolation.yaml
    │   └── 03-human-identity.yaml
    ├── agents/
    │   └── demo-invocations.yaml        # kubectl dry-run test manifests
    └── mcp-server/
        └── mcp-server-deployment.yaml   # Pod: mcp-server + authz-proxy sidecar
```

---

## Quick start (no cluster, UI only)

```bash
git clone https://github.com/your-username/mcp-authz-demo
cd mcp-authz-demo
pip install -r requirements.txt
python3 app.py
# http://localhost:5000
```

---

## Full demo with real Kyverno + kubernetes-mcp-server

### Prerequisites
- `kind`, `kubectl`, `helm`, `docker`, `python3`

### 1. Bootstrap everything

```bash
chmod +x setup.sh && ./setup.sh
```

This installs Kyverno, deploys `kubernetes-mcp-server` via Helm into `tenant-acme` and `tenant-globex`, and applies all four ClusterPolicies.

### 2. Run the dashboard

```bash
python3 app.py
# http://localhost:5000
```

### 3. Port-forward the AuthZ proxy

```bash
kubectl port-forward -n tenant-acme svc/mcp-server 8090:8090
```

### 4. Run the demo agent

```bash
# Full demo — all 5 scenarios
python3 agent/agent_client.py

# Single scenario
python3 agent/agent_client.py --single list-pods
python3 agent/agent_client.py --single delete-pod       # ❌ tool not in allowlist
python3 agent/agent_client.py --single cross-tenant     # ❌ cross-tenant blocked
```

### 5. Watch Kyverno block in real-time

```bash
# Watch policy violation events
sudo kubectl get events -A --field-selector reason=PolicyViolation -w

# Watch MCPToolInvocation CRs being created (and blocked)
sudo kubectl get mcptoolinvocations -A -w

# See audit annotations injected by the mutating policy
sudo kubectl get mcptoolinvocation -n tenant-acme -o yaml | grep mcp.security.io
```

### 6. Test directly with kubectl (dry-run through Kyverno)

```bash
# ALLOWED — SRE queries metrics in own tenant
sudo kubectl apply -f k8s/agents/demo-invocations.yaml --dry-run=server

# DENIED — individual scenarios
kubectl apply -f - --dry-run=server <<EOF
apiVersion: mcp.security.io/v1alpha1
kind: MCPToolInvocation
metadata:
  name: cross-tenant-test
  namespace: tenant-acme
spec:
  toolName: query_metrics
  agentId: sre-agent
  tenantId: tenant-globex    # ← wrong tenant → Kyverno blocks
  triggeredBy: alice@acme.com
  reason: testing
EOF
---

### 7. Teardown

`teardown.sh` removes the **full stack** in order — policies first, then workloads, then infrastructure. Run it after the demo or to start fresh before a rehearsal.

```bash
chmod +x teardown.sh && ./teardown.sh
```

Steps it runs:

| Step | What gets removed |
|------|-------------------|
| 1 | Kyverno ClusterPolicies (`01-tool-allowlist`, `02-tenant-isolation`, `03-human-identity`) |
| 2 | `kubernetes-mcp-server` Helm releases (`mcp-server-acme`, `mcp-server-globex`) |
| 3 | AuthZ proxy Deployment (`k8s/mcp-server/mcp-server-deployment.yaml`) |
| 4 | `MCPToolInvocation` CRD and all CRs across all namespaces |
| 5 | Tenant namespaces `tenant-acme`, `tenant-globex` + all ServiceAccounts and RBAC |
| 6 | Kyverno Helm release + `kyverno` namespace |
| 7 | kind cluster `mcp-authz-demo` |
| — | Local Docker image `mcp-authz-proxy:demo` |

To set the stack back up after teardown:

```bash
chmod +x setup.sh && ./setup.sh
```