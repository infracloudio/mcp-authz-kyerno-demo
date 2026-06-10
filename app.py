"""
MCP AuthZ Demo — Policy-Driven Tool Invocation Control
Talk: Closing the AuthZ Gap in MCP
Speaker: Oshi (InfraCloud Technologies / Improving)

Flask app that simulates MCP tool invocations and shows Kyverno policy
enforcement in real-time. Designed for live demo during talk.
"""

from flask import Flask, render_template, request, jsonify
import json
import time
import datetime
import subprocess
import os
import yaml

app = Flask(__name__)

# ──────────────────────────────────────────────
# Agent definitions — real tool names from
# containers/kubernetes-mcp-server (19 tools)
# ──────────────────────────────────────────────

AGENTS = {
    "sre-agent": {
        "label": "SRE Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-activity",
        "color": "blue",
        "allowed_tools": [
            "pods_list",
            "pods_list_in_namespace",
            "pods_get",
            "pods_log",
            "pods_top",
            "events_list",
            "namespaces_list",
            "nodes_top",
            "configuration_view",
        ],
    },
    "cost-agent": {
        "label": "Cost Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-chart-bar",
        "color": "green",
        "allowed_tools": [
            "nodes_stats_summary",
            "nodes_top",
            "nodes_log",
            "pods_top",
            "resources_list",
            "resources_get",
        ],
    },
    "remediation-agent": {
        "label": "Remediation Agent",
        "namespace": "agents",
        "risk": "high",
        "icon": "ti-tool",
        "color": "amber",
        "allowed_tools": [
            "pods_delete",
            "pods_exec",
            "pods_run",
            "resources_scale",
            "resources_create_or_update",
            "resources_delete",
        ],
    },
}

TENANTS = ["tenant-acme", "tenant-globex"]

# Real 19 tools from containers/kubernetes-mcp-server
ALL_TOOLS = [
    # ── Observability (sre-agent) ──────────────────────────────────────────
    {"name": "pods_list",              "category": "observability", "write": False},
    {"name": "pods_list_in_namespace", "category": "observability", "write": False},
    {"name": "pods_get",               "category": "observability", "write": False},
    {"name": "pods_log",               "category": "observability", "write": False},
    {"name": "pods_top",               "category": "observability", "write": False},
    {"name": "events_list",            "category": "observability", "write": False},
    {"name": "namespaces_list",        "category": "observability", "write": False},
    {"name": "nodes_top",              "category": "observability", "write": False},
    {"name": "configuration_view",     "category": "observability", "write": False},
    # ── Cost (cost-agent) ─────────────────────────────────────────────────
    {"name": "nodes_stats_summary",    "category": "cost",          "write": False},
    {"name": "nodes_log",              "category": "cost",          "write": False},
    {"name": "resources_list",         "category": "cost",          "write": False},
    {"name": "resources_get",          "category": "cost",          "write": False},
    # ── Remediation (remediation-agent) — write tools ─────────────────────
    {"name": "pods_delete",            "category": "remediation",   "write": True},
    {"name": "pods_exec",              "category": "remediation",   "write": True},
    {"name": "pods_run",               "category": "remediation",   "write": True},
    {"name": "resources_scale",        "category": "remediation",   "write": True},
    {"name": "resources_create_or_update", "category": "remediation", "write": True},
    {"name": "resources_delete",       "category": "remediation",   "write": True},
]

WRITE_TOOLS = [t["name"] for t in ALL_TOOLS if t["write"]]

# ──────────────────────────────────────────────
# Policy engine (simulated for demo)
# In real deployment this is Kyverno admission webhook
# ──────────────────────────────────────────────

def evaluate_policies(invocation: dict) -> dict:
    """
    Simulates Kyverno ValidatingPolicy / MutatingPolicy evaluation.
    Returns decision, policy_results, and audit annotations.
    """
    agent_id     = invocation.get("agentId", "")
    tool_name    = invocation.get("toolName", "")
    tenant_id    = invocation.get("tenantId", "")
    namespace    = invocation.get("namespace", "")
    triggered_by = invocation.get("triggeredBy", "").strip()

    results = []

    # ── Policy 1: Tool Allowlist (spec.agentId based) ─────────────────────
    agent = AGENTS.get(agent_id)
    if agent:
        if tool_name not in agent["allowed_tools"]:
            results.append({
                "policy": "mcp-tool-allowlist",
                "rule":   f"{agent_id}-allowlist",
                "result": "FAIL",
                "message": (
                    f"Agent '{agent_id}' is not permitted to invoke '{tool_name}'. "
                    f"Allowed: {', '.join(agent['allowed_tools'])}"
                ),
            })
        else:
            results.append({
                "policy": "mcp-tool-allowlist",
                "rule":   f"{agent_id}-allowlist",
                "result": "PASS",
                "message": f"Tool '{tool_name}' is in the allowlist for '{agent_id}'",
            })
    else:
        results.append({
            "policy": "mcp-tool-allowlist",
            "rule":   "unknown-agent",
            "result": "FAIL",
            "message": (
                f"Unknown agent '{agent_id}' — not registered. "
                "Permitted agents: sre-agent, cost-agent, remediation-agent"
            ),
        })

    # ── Policy 2: Tenant Isolation ────────────────────────────────────────
    if not tenant_id:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule":   "require-tenant-context",
            "result": "FAIL",
            "message": "MCPToolInvocation must include a non-empty tenantId in spec.",
        })
    elif tenant_id != namespace:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule":   "block-cross-tenant-invocations",
            "result": "FAIL",
            "message": (
                f"Cross-tenant invocation denied. "
                f"Agent namespace '{namespace}' does not match tenantId '{tenant_id}'."
            ),
        })
    else:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule":   "block-cross-tenant-invocations",
            "result": "PASS",
            "message": f"Tenant context '{tenant_id}' matches namespace '{namespace}'",
        })

    # ── Policy 3a: Human Identity Injection (mutating — always passes) ────
    results.append({
        "policy": "mcp-inject-human-identity",
        "rule":   "inject-human-identity-annotations",
        "result": "MUTATE",
        "message": (
            f"Injected: mcp.security.io/triggered-by={triggered_by or agent_id}, "
            f"mcp.security.io/triggered-at="
            f"{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}, "
            f"mcp.security.io/policy-version=v1"
        ),
    })

    # ── Policy 3b: Require Human Trigger for Write Tools ─────────────────
    if tool_name in WRITE_TOOLS:
        if not triggered_by:
            results.append({
                "policy": "mcp-require-human-trigger",
                "rule":   "require-human-trigger-for-write-tools",
                "result": "FAIL",
                "message": (
                    f"Write-capable tool '{tool_name}' requires a human triggeredBy field. "
                    "Automated invocations without explicit human context are denied."
                ),
            })
        else:
            results.append({
                "policy": "mcp-require-human-trigger",
                "rule":   "require-human-trigger-for-write-tools",
                "result": "PASS",
                "message": f"Human trigger '{triggered_by}' present for write tool '{tool_name}'",
            })

    # ── Final decision ────────────────────────────────────────────────────
    failed   = [r for r in results if r["result"] == "FAIL"]
    decision = "DENIED" if failed else "ALLOWED"

    return {
        "decision":        decision,
        "policy_results":  results,
        "failed_count":    len(failed),
        "pass_count":      len([r for r in results if r["result"] == "PASS"]),
        "audit_annotations": {
            "mcp.security.io/triggered-by":    triggered_by or agent_id,
            "mcp.security.io/triggered-at":    datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mcp.security.io/agent-id":        agent_id,
            "mcp.security.io/tenant-id":       tenant_id,
            "mcp.security.io/policy-version":  "v1",
            "mcp.security.io/decision":        decision,
        },
    }


def try_kubectl_apply(invocation: dict) -> dict:
    """
    Attempts to apply MCPToolInvocation to the real cluster via kubectl.
    Falls back to simulated evaluation if kubectl unavailable.
    """
    manifest = {
        "apiVersion": "mcp.security.io/v1alpha1",
        "kind":       "MCPToolInvocation",
        "metadata": {
            "generateName": "demo-",
            "namespace":    invocation.get("namespace", "tenant-acme"),
        },
        "spec": {
            "toolName":    invocation.get("toolName"),
            "agentId":     invocation.get("agentId"),
            "tenantId":    invocation.get("tenantId"),
            "triggeredBy": invocation.get("triggeredBy", ""),
            "reason":      invocation.get("reason", ""),
            "parameters":  invocation.get("parameters", {}),
        },
    }
    try:
        result = subprocess.run(
            ["kubectl", "apply", "-f", "-"],
            input=yaml.dump(manifest),
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {
            "kubectl_available": True,
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"kubectl_available": False}


# ──────────────────────────────────────────────
# Predefined demo scenarios
# Tool names match real kubernetes-mcp-server
# ──────────────────────────────────────────────

SCENARIOS = [
    {
        "id":          "allowed-sre-pods",
        "label":       "✅ SRE lists pods in own namespace (allowed)",
        "description": "SRE agent lists pods within its own tenant namespace. All policies pass.",
        "invocation": {
            "agentId":     "sre-agent",
            "toolName":    "pods_list_in_namespace",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason":      "Checking pod status during incident investigation",
            "parameters":  {"namespace": "tenant-acme"},
        },
    },
    {
        "id":          "denied-tool-allowlist",
        "label":       "❌ SRE tries to scale deployment (not in allowlist)",
        "description": "SRE agent attempts resources_scale — outside its allowlist. Policy 1 blocks.",
        "invocation": {
            "agentId":     "sre-agent",
            "toolName":    "resources_scale",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason":      "Trying to scale after seeing high latency",
            "parameters":  {
                "apiVersion": "apps/v1",
                "kind":       "Deployment",
                "name":       "checkout",
                "namespace":  "tenant-acme",
                "replicas":   5,
            },
        },
    },
    {
        "id":          "denied-cross-tenant",
        "label":       "❌ SRE crosses tenant boundary (cross-tenant blocked)",
        "description": "SRE agent in tenant-acme tries to list pods in tenant-globex. Policy 2 blocks.",
        "invocation": {
            "agentId":     "sre-agent",
            "toolName":    "pods_list_in_namespace",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-globex",
            "triggeredBy": "alice@acme.com",
            "reason":      "Checking Globex pods out of curiosity",
            "parameters":  {"namespace": "tenant-globex"},
        },
    },
    {
        "id":          "denied-no-human",
        "label":       "❌ Remediation deletes pod without human trigger",
        "description": "Autonomous remediation fires pods_delete without a human triggeredBy. Policy 3b blocks.",
        "invocation": {
            "agentId":     "remediation-agent",
            "toolName":    "pods_delete",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "",
            "reason":      "Auto-remediation triggered by alert rule",
            "parameters":  {"name": "checkout-7d9b4c-xkp2n", "namespace": "tenant-acme"},
        },
    },
    {
        "id":          "allowed-remediation",
        "label":       "✅ Remediation deletes pod with human approval",
        "description": "Remediation agent deletes pod with human context. All policies pass.",
        "invocation": {
            "agentId":     "remediation-agent",
            "toolName":    "pods_delete",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "bob@acme.com",
            "reason":      "Pod in CrashLoopBackOff, approved by on-call engineer Bob",
            "parameters":  {"name": "checkout-7d9b4c-xkp2n", "namespace": "tenant-acme"},
        },
    },
    {
        "id":          "allowed-cost-resources",
        "label":       "✅ Cost agent reads resource usage (allowed)",
        "description": "Cost agent lists resources for rightsizing analysis. All policies pass.",
        "invocation": {
            "agentId":     "cost-agent",
            "toolName":    "resources_list",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "carol@acme.com",
            "reason":      "Weekly rightsizing analysis",
            "parameters":  {"apiVersion": "apps/v1", "kind": "Deployment", "namespace": "tenant-acme"},
        },
    },
    {
        "id":          "denied-cost-write",
        "label":       "❌ Cost agent tries to scale (not in allowlist)",
        "description": "Cost agent attempts resources_scale — outside its allowlist. Policy 1 blocks.",
        "invocation": {
            "agentId":     "cost-agent",
            "toolName":    "resources_scale",
            "namespace":   "tenant-acme",
            "tenantId":    "tenant-acme",
            "triggeredBy": "carol@acme.com",
            "reason":      "Trying to right-size deployment directly",
            "parameters":  {
                "apiVersion": "apps/v1",
                "kind":       "Deployment",
                "name":       "checkout",
                "namespace":  "tenant-acme",
                "replicas":   2,
            },
        },
    },
]


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        agents=AGENTS,
        tenants=TENANTS,
        all_tools=ALL_TOOLS,
        scenarios=SCENARIOS,
    )


@app.route("/api/invoke", methods=["POST"])
def invoke_tool():
    data = request.get_json()

    # Simulate admission latency for realism
    time.sleep(0.3)

    result       = evaluate_policies(data)
    kubectl_result = try_kubectl_apply(data)

    return jsonify({
        **result,
        "invocation": data,
        "kubectl":    kubectl_result,
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
    })


@app.route("/api/scenario/<scenario_id>")
def get_scenario(scenario_id):
    scenario = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404
    return jsonify(scenario)


@app.route("/api/agents")
def get_agents():
    return jsonify(AGENTS)


@app.route("/api/tools")
def get_tools():
    return jsonify(ALL_TOOLS)


@app.route("/api/policies")
def get_policies():
    policies_dir = os.path.join(os.path.dirname(__file__), "k8s", "policies")
    policies = []
    if os.path.exists(policies_dir):
        for fname in sorted(os.listdir(policies_dir)):
            if fname.endswith(".yaml"):
                with open(os.path.join(policies_dir, fname)) as f:
                    policies.append({"filename": fname, "content": f.read()})
    return jsonify(policies)


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)