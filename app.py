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
# Demo data: agent definitions and their tools
# ──────────────────────────────────────────────

AGENTS = {
    "sre-agent": {
        "label": "SRE Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-activity",
        "color": "blue",
        "allowed_tools": ["query_metrics", "list_incidents", "get_runbook", "check_slo"],
    },
    "cost-agent": {
        "label": "Cost Agent",
        "namespace": "agents",
        "risk": "low",
        "icon": "ti-chart-bar",
        "color": "green",
        "allowed_tools": ["get_resource_usage", "list_rightsizing_recommendations", "get_billing_summary"],
    },
    "remediation-agent": {
        "label": "Remediation Agent",
        "namespace": "agents",
        "risk": "high",
        "icon": "ti-tool",
        "color": "amber",
        "allowed_tools": ["restart_pod", "scale_deployment", "rollback_deployment"],
    },
}

TENANTS = ["tenant-acme", "tenant-globex"]

ALL_TOOLS = [
    # observability tools
    {"name": "query_metrics",    "category": "observability", "write": False},
    {"name": "list_incidents",   "category": "observability", "write": False},
    {"name": "get_runbook",      "category": "observability", "write": False},
    {"name": "check_slo",        "category": "observability", "write": False},
    # cost tools
    {"name": "get_resource_usage",                  "category": "cost", "write": False},
    {"name": "list_rightsizing_recommendations",    "category": "cost", "write": False},
    {"name": "get_billing_summary",                 "category": "cost", "write": False},
    # remediation tools (write)
    {"name": "restart_pod",         "category": "remediation", "write": True},
    {"name": "scale_deployment",    "category": "remediation", "write": True},
    {"name": "rollback_deployment", "category": "remediation", "write": True},
    {"name": "delete_resource",     "category": "remediation", "write": True},
]

WRITE_TOOLS = [t["name"] for t in ALL_TOOLS if t["write"]]

# ──────────────────────────────────────────────
# Policy engine (simulated for demo)
# In real deployment this is Kyverno admission webhook
# ──────────────────────────────────────────────

def evaluate_policies(invocation: dict) -> dict:
    """
    Simulates Kyverno ClusterPolicy evaluation.
    Returns a dict with decision, violated_policy, and explanation.
    """
    agent_id     = invocation.get("agentId", "")
    tool_name    = invocation.get("toolName", "")
    tenant_id    = invocation.get("tenantId", "")
    namespace    = invocation.get("namespace", "")
    triggered_by = invocation.get("triggeredBy", "").strip()

    results = []

    # ── Policy 1: Tool Allowlist ──────────────────────────────────────────
    agent = AGENTS.get(agent_id)
    if agent:
        if tool_name not in agent["allowed_tools"]:
            results.append({
                "policy": "mcp-tool-allowlist",
                "rule": f"{agent_id}-allowlist",
                "result": "FAIL",
                "message": (
                    f"Agent '{agent_id}' is not permitted to invoke tool '{tool_name}'. "
                    f"Allowed: {', '.join(agent['allowed_tools'])}"
                ),
            })
        else:
            results.append({
                "policy": "mcp-tool-allowlist",
                "rule": f"{agent_id}-allowlist",
                "result": "PASS",
                "message": f"Tool '{tool_name}' is in the allowlist for '{agent_id}'",
            })
    else:
        results.append({
            "policy": "mcp-tool-allowlist",
            "rule": "unknown-agent",
            "result": "FAIL",
            "message": f"Unknown agent identity '{agent_id}' — no allowlist found. Deny by default.",
        })

    # ── Policy 2: Tenant Isolation ────────────────────────────────────────
    if not tenant_id:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule": "require-tenant-context",
            "result": "FAIL",
            "message": "MCPToolInvocation must include a non-empty tenantId.",
        })
    elif tenant_id != namespace:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule": "block-cross-tenant-invocations",
            "result": "FAIL",
            "message": (
                f"Cross-tenant invocation denied. "
                f"Agent namespace '{namespace}' ≠ tenantId '{tenant_id}'."
            ),
        })
    else:
        results.append({
            "policy": "mcp-tenant-isolation",
            "rule": "block-cross-tenant-invocations",
            "result": "PASS",
            "message": f"Tenant context '{tenant_id}' matches namespace '{namespace}'",
        })

    # ── Policy 3: Human Identity (mutating — always passes, just annotates) ──
    results.append({
        "policy": "mcp-inject-human-identity",
        "rule": "inject-human-identity-annotations",
        "result": "MUTATE",
        "message": (
            f"Injected: mcp.security.io/triggered-by={triggered_by or agent_id}, "
            f"mcp.security.io/triggered-at={datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}"
        ),
    })

    # ── Policy 4: Require Human Trigger for Write Tools ───────────────────
    if tool_name in WRITE_TOOLS:
        if not triggered_by:
            results.append({
                "policy": "mcp-require-human-trigger",
                "rule": "require-human-trigger-for-write-tools",
                "result": "FAIL",
                "message": (
                    f"Write-capable tool '{tool_name}' requires a human triggeredBy field. "
                    "Automated invocations without explicit human context are denied."
                ),
            })
        else:
            results.append({
                "policy": "mcp-require-human-trigger",
                "rule": "require-human-trigger-for-write-tools",
                "result": "PASS",
                "message": f"Human trigger '{triggered_by}' is present for write tool '{tool_name}'",
            })

    # ── Final decision ────────────────────────────────────────────────────
    failed = [r for r in results if r["result"] == "FAIL"]
    decision = "DENIED" if failed else "ALLOWED"

    return {
        "decision": decision,
        "policy_results": results,
        "failed_count": len(failed),
        "pass_count": len([r for r in results if r["result"] == "PASS"]),
        "audit_annotations": {
            "mcp.security.io/triggered-by": triggered_by or agent_id,
            "mcp.security.io/triggered-at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mcp.security.io/agent-id": agent_id,
            "mcp.security.io/tenant-id": tenant_id,
            "mcp.security.io/policy-version": "v1",
            "mcp.security.io/decision": decision,
        },
    }


def try_kubectl_apply(invocation: dict) -> dict:
    """
    Attempts to apply the MCPToolInvocation to the real cluster if kubectl is available.
    Falls back to simulated evaluation if not in cluster context.
    """
    # Build the manifest
    manifest = {
        "apiVersion": "mcp.security.io/v1alpha1",
        "kind": "MCPToolInvocation",
        "metadata": {
            "generateName": "demo-",
            "namespace": invocation.get("namespace", "tenant-acme"),
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
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"kubectl_available": False}


# ──────────────────────────────────────────────
# Predefined demo scenarios for the talk
# ──────────────────────────────────────────────

SCENARIOS = [
    {
        "id": "allowed-sre-metrics",
        "label": "✅ SRE queries metrics (allowed)",
        "description": "SRE agent queries metrics within its own tenant. All policies pass.",
        "invocation": {
            "agentId": "sre-agent",
            "toolName": "query_metrics",
            "namespace": "tenant-acme",
            "tenantId": "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason": "Investigating elevated p99 latency on checkout",
            "parameters": {"service": "checkout", "metric": "http_request_duration_p99"},
        },
    },
    {
        "id": "denied-tool-allowlist",
        "label": "❌ SRE tries to scale deployment (tool not in allowlist)",
        "description": "SRE agent attempts to invoke scale_deployment — outside its allowlist. Policy 1 blocks.",
        "invocation": {
            "agentId": "sre-agent",
            "toolName": "scale_deployment",
            "namespace": "tenant-acme",
            "tenantId": "tenant-acme",
            "triggeredBy": "alice@acme.com",
            "reason": "Trying to scale after seeing high latency",
            "parameters": {"deployment": "checkout", "replicas": 5},
        },
    },
    {
        "id": "denied-cross-tenant",
        "label": "❌ SRE crosses tenant boundary (cross-tenant blocked)",
        "description": "SRE agent in tenant-acme namespace tries to access tenant-globex data. Policy 2 blocks.",
        "invocation": {
            "agentId": "sre-agent",
            "toolName": "query_metrics",
            "namespace": "tenant-acme",
            "tenantId": "tenant-globex",
            "triggeredBy": "alice@acme.com",
            "reason": "Checking Globex error rate out of curiosity",
            "parameters": {"service": "payments", "metric": "error_rate"},
        },
    },
    {
        "id": "denied-no-human",
        "label": "❌ Remediation restarts pod without human trigger",
        "description": "Automated remediation fires without a human triggeredBy. Policy 4 blocks write tool.",
        "invocation": {
            "agentId": "remediation-agent",
            "toolName": "restart_pod",
            "namespace": "tenant-acme",
            "tenantId": "tenant-acme",
            "triggeredBy": "",
            "reason": "Auto-remediation triggered by alert rule",
            "parameters": {"pod": "checkout-7d9b4c-xkp2n"},
        },
    },
    {
        "id": "allowed-remediation",
        "label": "✅ Remediation restarts pod with human approval",
        "description": "Remediation agent restarts pod with human context. All policies pass.",
        "invocation": {
            "agentId": "remediation-agent",
            "toolName": "restart_pod",
            "namespace": "tenant-acme",
            "tenantId": "tenant-acme",
            "triggeredBy": "bob@acme.com",
            "reason": "Pod in CrashLoopBackOff, approved by on-call engineer Bob",
            "parameters": {"pod": "checkout-7d9b4c-xkp2n"},
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

    # Simulate network latency for realism
    time.sleep(0.3)

    # Run policy evaluation
    result = evaluate_policies(data)

    # Try real kubectl if available
    kubectl_result = try_kubectl_apply(data)

    return jsonify({
        **result,
        "invocation": data,
        "kubectl": kubectl_result,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
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
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
