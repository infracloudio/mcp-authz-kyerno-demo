/* MCP AuthZ Demo — Frontend JS */

const invokeBtn   = document.getElementById('invokeBtn');
const emptyState  = document.getElementById('emptyState');
const banner      = document.getElementById('decisionBanner');
const decisionIcon  = document.getElementById('decisionIcon');
const decisionLabel = document.getElementById('decisionLabel');
const decisionSub   = document.getElementById('decisionSub');
const summaryEl     = document.getElementById('invocationSummary');
const summaryGrid   = document.getElementById('summaryGrid');
const policyResultsEl = document.getElementById('policyResults');
const policyList    = document.getElementById('policyList');
const auditSection  = document.getElementById('auditSection');
const auditTable    = document.getElementById('auditTable');

// ── Scenario loading ──────────────────────────────────────────────────────────

document.querySelectorAll('.scenario-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const id = btn.dataset.scenario;
    const res = await fetch(`/api/scenario/${id}`);
    const scenario = await res.json();
    const inv = scenario.invocation;

    document.getElementById('agentId').value     = inv.agentId     || '';
    document.getElementById('toolName').value    = inv.toolName    || '';
    document.getElementById('namespace').value   = inv.namespace   || '';
    document.getElementById('tenantId').value    = inv.tenantId    || '';
    document.getElementById('triggeredBy').value = inv.triggeredBy || '';
    document.getElementById('reason').value      = inv.reason      || '';

    // Auto-invoke
    await runInvocation(inv);
  });
});

// ── Manual invoke ─────────────────────────────────────────────────────────────

invokeBtn.addEventListener('click', async () => {
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));

  const inv = {
    agentId:     document.getElementById('agentId').value,
    toolName:    document.getElementById('toolName').value,
    namespace:   document.getElementById('namespace').value,
    tenantId:    document.getElementById('tenantId').value,
    triggeredBy: document.getElementById('triggeredBy').value.trim(),
    reason:      document.getElementById('reason').value.trim(),
    parameters:  {},
  };
  await runInvocation(inv);
});

// ── Core invocation runner ────────────────────────────────────────────────────

async function runInvocation(inv) {
  invokeBtn.disabled = true;
  invokeBtn.innerHTML = '<span class="spinner"></span> Evaluating...';

  try {
    const res = await fetch('/api/invoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(inv),
    });
    const data = await res.json();
    renderResult(data);
  } catch (err) {
    console.error(err);
  } finally {
    invokeBtn.disabled = false;
    invokeBtn.innerHTML = '<i class="ti ti-send"></i> Invoke Tool';
  }
}

// ── Render result ─────────────────────────────────────────────────────────────

function renderResult(data) {
  const allowed = data.decision === 'ALLOWED';

  // Hide empty state
  emptyState.classList.add('hidden');

  // Decision banner
  banner.classList.remove('hidden', 'allowed', 'denied');
  banner.classList.add(allowed ? 'allowed' : 'denied');
  decisionIcon.innerHTML = allowed
    ? '<i class="ti ti-shield-check"></i>'
    : '<i class="ti ti-shield-x"></i>';
  decisionLabel.textContent = allowed ? '✅ ALLOWED' : '❌ DENIED';
  decisionSub.textContent = allowed
    ? `All ${data.pass_count} policies passed — invocation proceeds to MCP server`
    : `${data.failed_count} policy violation(s) — invocation blocked at admission`;

  // Invocation summary
  summaryEl.classList.remove('hidden');
  const inv = data.invocation;
  summaryGrid.innerHTML = [
    ['Agent',        inv.agentId],
    ['Tool',         inv.toolName],
    ['Namespace',    inv.namespace],
    ['Tenant ID',    inv.tenantId],
    ['Triggered By', inv.triggeredBy || '(none)'],
    ['Reason',       inv.reason || '(none)'],
  ].map(([k, v]) => `
    <div class="summary-item">
      <span class="summary-key">${k}</span>
      <span class="summary-val">${v}</span>
    </div>
  `).join('');

  // Policy results
  policyResultsEl.classList.remove('hidden');
  policyList.innerHTML = data.policy_results.map(r => {
    const cls = r.result.toLowerCase();
    const label = r.result === 'MUTATE' ? 'MUTATE' : r.result;
    return `
      <div class="policy-item ${cls}">
        <span class="policy-badge ${cls}">${label}</span>
        <div class="policy-detail">
          <div class="policy-name">${r.policy}</div>
          <div class="policy-rule">rule: ${r.rule}</div>
          <div class="policy-msg">${r.message}</div>
        </div>
      </div>
    `;
  }).join('');

  // Audit annotations
  auditSection.classList.remove('hidden');
  const ann = data.audit_annotations;
  auditTable.innerHTML = Object.entries(ann).map(([k, v]) => `
    <div class="audit-row">
      <span class="audit-key">${k}</span>
      <span class="audit-sep">:</span>
      <span class="audit-val">${v}</span>
    </div>
  `).join('');
}
