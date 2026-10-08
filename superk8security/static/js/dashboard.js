// SuperK8Security Real-Time Dashboard Client with 1-Minute Periodic Breach Engine

let currentPods = [];
let currentIncidents = [];
let currentMitigations = [];
let selectedIncidentId = null;
let activeHitlMitigationId = null;
let periodicBreachState = {
  enabled: true,
  interval_seconds: 60,
  next_breach_in_seconds: 60
};
let countdownInterval = null;

let socket = null;
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsPath = window.location.pathname.startsWith('/devmode') ? '/devmode/ws' : '/ws';
  const wsUrl = `${protocol}//${window.location.host}${wsPath}`;
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    console.log("SuperK8Security WebSocket Connected.");
    document.getElementById("live-indicator").innerText = "LIVE (CONNECTED)";
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "INITIAL_STATE" || data.type === "CLUSTER_UPDATE") {
        currentPods = data.pods || [];
        currentIncidents = data.incidents || [];
        currentMitigations = data.mitigations || [];
        updateMetrics(data.stats);
        renderPods(currentPods);
        renderIncidents(currentIncidents);
        renderHitlProposals(currentMitigations);
        renderEventHistory(currentIncidents);
        if (data.periodic_breach) {
          updatePeriodicBreachUI(data.periodic_breach);
        }
        if (selectedIncidentId) {
          const inc = currentIncidents.find(i => i.incident_id === selectedIncidentId);
          if (inc) renderTrace(inc);
        }
      }
    } catch (e) {
      console.error("Error parsing WS message:", e);
    }
  };

  socket.onclose = () => {
    document.getElementById("live-indicator").innerText = "RECONNECTING...";
    setTimeout(initWebSocket, 2000);
  };
}

function updatePeriodicBreachUI(state) {
  periodicBreachState = state;
  const badge = document.getElementById("campaign-status-badge");
  const toggleBtn = document.getElementById("campaign-toggle-btn");
  const countdown = document.getElementById("campaign-countdown");

  if (!badge || !toggleBtn || !countdown) return;

  if (state.enabled) {
    badge.className = "px-2 py-0.2 rounded font-mono text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800";
    badge.innerHTML = `<i class="fa-solid fa-play text-xs mr-1 text-emerald-400"></i> ACTIVE (1m INTERVAL)`;
    toggleBtn.innerHTML = `<i class="fa-solid fa-pause"></i> Pause`;
  } else {
    badge.className = "px-2 py-0.2 rounded font-mono text-[10px] bg-amber-950 text-amber-300 border border-amber-800";
    badge.innerHTML = `<i class="fa-solid fa-pause text-xs mr-1 text-amber-400"></i> PAUSED`;
    toggleBtn.innerHTML = `<i class="fa-solid fa-play"></i> Resume`;
  }

  countdown.innerText = `${state.next_breach_in_seconds}s`;
}

// Client-side smooth ticking countdown
if (!countdownInterval) {
  countdownInterval = setInterval(() => {
    if (periodicBreachState && periodicBreachState.enabled) {
      if (periodicBreachState.next_breach_in_seconds > 0) {
        periodicBreachState.next_breach_in_seconds -= 1;
        const countdown = document.getElementById("campaign-countdown");
        if (countdown) {
          countdown.innerText = `${periodicBreachState.next_breach_in_seconds}s`;
        }
      }
    }
  }, 1000);
}

async function togglePeriodicBreach() {
  try {
    const res = await fetch('/api/periodic-breach/toggle', { method: 'POST' });
    const data = await res.json();
    console.log("Toggled periodic breach:", data);
  } catch (e) {
    console.error("Error toggling periodic breach:", e);
  }
}

async function triggerNowPeriodicBreach() {
  try {
    const res = await fetch('/api/periodic-breach/trigger-now', { method: 'POST' });
    const data = await res.json();
    if (data.incident) {
      selectedIncidentId = data.incident.incident_id;
      renderTrace(data.incident);
    }
  } catch (e) {
    console.error("Error triggering periodic breach:", e);
  }
}

async function triggerSpecificBreach(scenario) {
  try {
    const res = await fetch(`/api/simulate/attack/${scenario}`, { method: 'POST' });
    const data = await res.json();
    if (data.incident) {
      selectedIncidentId = data.incident.incident_id;
      renderTrace(data.incident);
    }
  } catch (e) {
    console.error(`Error triggering attack '${scenario}':`, e);
  }
}

function updateMetrics(stats) {
  if (!stats) return;
  document.getElementById("metric-total-pods").innerText = currentPods.length;
  const quarantinedCount = currentPods.filter(p => p.quarantined).length;
  document.getElementById("metric-sandboxed").innerText = `${currentPods.length - quarantinedCount} / ${currentPods.length}`;
  document.getElementById("metric-pending-hitl").innerText = stats.pending_mitigations || 0;
  document.getElementById("metric-critical").innerText = stats.critical_incidents || 0;
  document.getElementById("metric-high-med").innerText = (stats.high_incidents || 0) + (stats.medium_incidents || 0);
  document.getElementById("metric-remediations").innerText = stats.remediations_executed || 0;
}

// RENDER AUTO-CORRECT & HUMAN-IN-THE-LOOP (HITL) PROPOSALS
function renderHitlProposals(mitigations) {
  const container = document.getElementById("hitl-proposals-container");
  const countBadge = document.getElementById("hitl-queue-count");
  if (!container) return;

  const pending = mitigations.filter(m => m.status === "AWAITING_APPROVAL");
  countBadge.innerText = `${pending.length} Pending Approval`;

  if (mitigations.length === 0) {
    container.innerHTML = `
      <div class="col-span-full text-center py-5 text-slate-500 text-xs italic bg-slate-950/40 rounded-lg border border-slate-800">
        <i class="fa-solid fa-circle-check text-emerald-500 text-lg mb-1"></i><br>
        No pending mitigation proposals. All agent workloads are securely sandboxed.
      </div>
    `;
    return;
  }

  container.innerHTML = mitigations.map(m => {
    const isPending = m.status === "AWAITING_APPROVAL";
    const isApproved = m.status === "APPROVED";
    
    let statusBadge = "bg-purple-950 text-purple-300 border-purple-700 animate-pulse";
    let icon = "fa-hourglass-half text-purple-400";
    if (isApproved) {
      statusBadge = "bg-emerald-950 text-emerald-300 border-emerald-800";
      icon = "fa-circle-check text-emerald-400";
    } else if (m.status === "REJECTED") {
      statusBadge = "bg-rose-950 text-rose-300 border-rose-800";
      icon = "fa-circle-xmark text-rose-400";
    }

    return `
      <div class="p-2.5 rounded-xl bg-slate-900/90 border ${isPending ? 'border-purple-600/80 shadow-md shadow-purple-950/50' : 'border-slate-800'} flex flex-col justify-between text-xs">
        <div>
          <div class="flex items-center justify-between mb-1">
            <div class="flex items-center space-x-1.5">
              <span class="px-2 py-0.2 rounded border text-[9.5px] font-bold font-mono ${statusBadge}">
                <i class="fa-solid ${icon} mr-1"></i> ${m.status}
              </span>
              <span class="text-cyan-400 font-bold font-mono text-[10.5px]">${m.mitigation_id}</span>
            </div>
            <span class="text-[9.5px] text-emerald-400 font-mono bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-800">
              ${m.confidence_score}% Confidence
            </span>
          </div>

          <h4 class="font-bold text-white text-xs mb-0.5 line-clamp-1">${m.title}</h4>
          <p class="text-slate-400 text-[10.5px] mb-1.5 leading-relaxed line-clamp-2">${m.recommended_action}</p>

          <div class="bg-slate-950 p-1.5 rounded-lg border border-slate-800/80 text-[9.5px] font-mono mb-2">
            <div class="text-slate-400"><span class="text-slate-500">Agent:</span> <span class="text-cyan-300">${m.target_agent}</span> (ns: ${m.target_namespace})</div>
            <div class="text-slate-400"><span class="text-slate-500">Action:</span> <span class="text-purple-300">${m.action_type}</span></div>
          </div>
        </div>

        <div class="pt-1.5 border-t border-slate-800 flex items-center justify-between gap-2">
          ${isPending ? `
            <button onclick="openHitlModal('${m.mitigation_id}')" class="w-full py-1.5 px-3 rounded-lg bg-gradient-to-r from-purple-700 to-indigo-600 hover:from-purple-600 hover:to-indigo-500 text-white font-bold transition flex items-center justify-center gap-1.5 shadow-md shadow-purple-900/40 text-[10.5px]">
              <i class="fa-solid fa-user-check"></i> Review &amp; Execute (HITL)
            </button>
          ` : `
            <div class="text-[9.5px] font-mono text-slate-400 flex items-center justify-between w-full">
              <span>By: <strong class="text-slate-200">${m.reviewed_by || 'Operator'}</strong></span>
              <button onclick="openHitlModal('${m.mitigation_id}')" class="text-cyan-400 underline text-[10px]">Inspect Diff &rarr;</button>
            </div>
          `}
        </div>
      </div>
    `;
  }).join('');
}

function openHitlModal(mitigationId) {
  const m = currentMitigations.find(item => item.mitigation_id === mitigationId);
  if (!m) return;

  activeHitlMitigationId = mitigationId;

  document.getElementById("hitl-modal-id").innerText = m.mitigation_id;
  document.getElementById("hitl-modal-title").innerText = m.title;

  const statusBadge = document.getElementById("hitl-modal-status");
  statusBadge.innerText = m.status;
  if (m.status === "APPROVED") {
    statusBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-700";
  } else if (m.status === "REJECTED") {
    statusBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-700";
  } else {
    statusBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-purple-950 text-purple-300 border border-purple-700";
  }

  const modalBody = document.getElementById("hitl-modal-body");
  modalBody.innerHTML = `
    <div class="grid grid-cols-2 md:grid-cols-4 gap-2.5 bg-slate-950 p-3 rounded-xl border border-slate-800 text-[11px]">
      <div>
        <span class="text-slate-500 block text-[9.5px] uppercase">Incident ID</span>
        <span class="text-cyan-400 font-bold">${m.incident_id}</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[9.5px] uppercase">Target Agent</span>
        <span class="text-white font-bold">${m.target_agent}</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[9.5px] uppercase">Namespace</span>
        <span class="text-indigo-400 font-bold">${m.target_namespace}</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[9.5px] uppercase">Confidence</span>
        <span class="text-emerald-400 font-bold">${m.confidence_score}%</span>
      </div>
    </div>

    <div class="bg-slate-900/70 p-3 rounded-xl border border-slate-800">
      <div class="text-purple-300 font-bold mb-1 flex items-center gap-1.5 text-xs">
        <i class="fa-solid fa-wand-magic-sparkles text-purple-400"></i> Auto-Correct Policy Recommendation:
      </div>
      <p class="text-slate-300 text-xs leading-relaxed font-sans">
        ${m.recommended_action}
      </p>
    </div>

    <div>
      <div class="flex items-center justify-between mb-1 text-[11px]">
        <span class="text-slate-400 font-semibold font-sans">Proposed Policy Patch / Manifest Diff:</span>
        <span class="text-cyan-400 font-mono text-[10px]">Cilium / Istio / RBAC</span>
      </div>
      <pre class="bg-black/90 text-emerald-400 p-3 rounded-xl border border-slate-800 text-[11px] overflow-x-auto scrollbar-thin max-h-48 leading-relaxed font-mono">${escapeHtml(m.action_diff || '# No diff content available')}</pre>
    </div>

    <div>
      <label class="block text-slate-400 font-sans text-xs mb-1">Operator Notes / Rationale (Logged for Compliance Audit):</label>
      <input type="text" id="hitl-notes-input" value="${m.operator_notes || 'Auto-correct verified and approved by human operator.'}" class="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg p-2 font-mono focus:border-cyan-500 focus:outline-none">
    </div>
  `;

  document.getElementById("hitl-action-modal").classList.remove("hidden");
}

function closeHitlModal() {
  document.getElementById("hitl-action-modal").classList.add("hidden");
  activeHitlMitigationId = null;
}

async function submitHitlAction(action) {
  if (!activeHitlMitigationId) return;

  const operatorName = document.getElementById("hitl-operator-input").value || "Lead Security Architect";
  const operatorNotes = document.getElementById("hitl-notes-input").value || "";

  try {
    const res = await fetch(`/api/mitigations/${activeHitlMitigationId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        operator_name: operatorName,
        action: action,
        operator_notes: operatorNotes
      })
    });
    const data = await res.json();
    if (data.status === "SUCCESS") {
      closeHitlModal();
    }
  } catch (e) {
    console.error("Failed to submit HITL action:", e);
  }
}

function renderPods(pods) {
  const container = document.getElementById("pods-grid");
  if (!container) return;

  container.innerHTML = pods.map(pod => {
    const isQuarantined = pod.quarantined;
    const borderClass = isQuarantined 
      ? "border-rose-600 bg-rose-950/20 danger-glow" 
      : "border-slate-800 bg-slate-900/40 hover:border-slate-700";
    
    const badgeClass = isQuarantined
      ? "bg-rose-950 text-rose-300 border-rose-800"
      : "bg-emerald-950 text-emerald-400 border-emerald-800";

    const statusIcon = isQuarantined
      ? '<i class="fa-solid fa-ban text-rose-500 mr-1"></i> Quarantined'
      : '<i class="fa-solid fa-circle-check text-emerald-500 mr-1"></i> Running (Sandboxed)';

    return `
      <div onclick="openPodModal('${pod.pod_name}')" class="p-2.5 rounded-xl border ${borderClass} transition cursor-pointer flex flex-col justify-between">
        <div>
          <div class="flex items-start justify-between mb-1">
            <div>
              <div class="flex items-center space-x-1.5">
                <span class="font-bold text-xs text-white">${pod.agent_name}</span>
                <span class="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">ns: ${pod.namespace}</span>
              </div>
              <p class="text-[10px] text-slate-400 mt-0.5 line-clamp-1">${pod.manifest.role}</p>
            </div>
            <span class="text-[9px] px-2 py-0.5 rounded-full border font-mono ${badgeClass}">
              ${statusIcon}
            </span>
          </div>

          <div class="grid grid-cols-2 gap-1 text-[9.5px] text-slate-400 font-mono mt-1 bg-slate-950/50 p-1.5 rounded-lg border border-slate-900">
            <div><span class="text-slate-500">IP:</span> <span class="text-slate-300">${pod.ip}</span></div>
            <div><span class="text-slate-500">Node:</span> <span class="text-slate-300">${pod.node}</span></div>
            <div><span class="text-slate-500">Conns:</span> <span class="text-slate-300">${pod.active_connections}</span></div>
            <div><span class="text-slate-500">Trust:</span> <span class="${pod.security_score < 70 ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${pod.security_score}/100</span></div>
          </div>
        </div>

        ${isQuarantined ? `
          <div class="mt-1.5 text-[9px] font-mono text-rose-300 bg-rose-950/40 p-1 rounded border border-rose-800/80 flex items-center justify-between">
            <span class="truncate"><i class="fa-solid fa-shield-virus"></i> ${pod.quarantine_reason || 'Rogue violation'}</span>
            <span class="text-purple-400 font-bold ml-1">HITL Available</span>
          </div>
        ` : `
          <div class="mt-1.5 text-[9px] font-mono text-cyan-400 flex items-center justify-between">
            <span class="truncate"><i class="fa-solid fa-lock text-slate-500"></i> Scope: ${pod.manifest.allowed_data_scopes.join(', ')}</span>
            <span class="text-slate-500">Inspect &rarr;</span>
          </div>
        `}
      </div>
    `;
  }).join('');
}

function renderIncidents(incidents) {
  const container = document.getElementById("incidents-feed");
  const counter = document.getElementById("incident-counter");
  if (!container) return;

  counter.innerText = `${incidents.length} events logged`;

  if (incidents.length === 0) {
    container.innerHTML = `
      <div class="text-center py-6 text-slate-500 text-xs italic">
        <i class="fa-solid fa-shield-cat text-2xl mb-1 text-slate-600"></i><br>
        SuperK8Security is actively monitoring ingress, egress & sandboxes.<br>
        No active breaches. Next rotating breach triggers in &lt;1m.
      </div>
    `;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const isSelected = inc.incident_id === selectedIncidentId;
    let badgeColor = "bg-amber-950 text-amber-300 border-amber-800";
    let icon = "fa-triangle-exclamation text-amber-400";
    if (inc.severity === "CRITICAL") {
      badgeColor = "bg-rose-950 text-rose-300 border-rose-800 animate-pulse";
      icon = "fa-radiation text-rose-400";
    } else if (inc.severity === "HIGH") {
      badgeColor = "bg-orange-950 text-orange-300 border-orange-800";
      icon = "fa-skull-crossbones text-orange-400";
    }

    const itemBorder = isSelected ? "border-cyan-500 bg-slate-800/90" : "border-slate-800 bg-slate-900/60 hover:border-slate-700";

    return `
      <div onclick="selectIncident('${inc.incident_id}')" class="p-1.5 rounded-lg border ${itemBorder} transition cursor-pointer text-xs">
        <div class="flex items-center justify-between mb-0.5">
          <div class="flex items-center space-x-1.5">
            <span class="px-1.5 py-0.2 rounded border font-mono text-[8.5px] ${badgeColor}">
              <i class="fa-solid ${icon} mr-0.5"></i> ${inc.severity}
            </span>
            <span class="font-bold text-slate-200 text-xs truncate max-w-[190px]">${inc.title}</span>
          </div>
          <span class="text-[9px] text-slate-500 font-mono">${new Date(inc.timestamp * 1000).toLocaleTimeString()}</span>
        </div>
        <p class="text-slate-400 text-[10px] line-clamp-1">${inc.description}</p>
      </div>
    `;
  }).join('');
}

function renderEventHistory(incidents) {
  const tbody = document.getElementById("history-table-body");
  const countLabel = document.getElementById("history-total-count");
  const severityFilter = document.getElementById("history-severity-filter").value;

  if (!tbody) return;

  let filtered = incidents;
  if (severityFilter !== "ALL") {
    filtered = incidents.filter(i => i.severity === severityFilter);
  }

  countLabel.innerText = `${incidents.length} Recorded Incidents`;

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="py-6 text-center text-slate-500 italic">
          No security events matching filter. Rotating breach triggers automatically every minute.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(inc => {
    let severityClass = "text-amber-400 bg-amber-950/60 border-amber-800";
    if (inc.severity === "CRITICAL") {
      severityClass = "text-rose-400 bg-rose-950/80 border-rose-800";
    } else if (inc.severity === "HIGH") {
      severityClass = "text-orange-400 bg-orange-950/80 border-orange-800";
    }

    const timeStr = new Date(inc.timestamp * 1000).toLocaleTimeString();
    const hasMitigation = inc.mitigation != null;

    return `
      <tr onclick="openIncidentDetailsModal('${inc.incident_id}')" class="hover:bg-slate-900/80 transition cursor-pointer border-b border-slate-800/60">
        <td class="py-2 px-3 text-slate-400 whitespace-nowrap">${timeStr}</td>
        <td class="py-2 px-3 text-cyan-400 font-bold whitespace-nowrap">${inc.incident_id}</td>
        <td class="py-2 px-3 whitespace-nowrap">
          <span class="px-2 py-0.5 rounded border text-[9px] font-bold ${severityClass}">
            ${inc.severity}
          </span>
        </td>
        <td class="py-2 px-3 text-slate-200 whitespace-nowrap">${inc.category}</td>
        <td class="py-2 px-3 whitespace-nowrap">
          <div class="font-bold text-white">${inc.agent_name}</div>
          <div class="text-[9px] text-slate-400">${inc.pod_name.substring(0, 20)}...</div>
        </td>
        <td class="py-2 px-3 text-cyan-400 whitespace-nowrap font-bold">${inc.namespace}</td>
        <td class="py-2 px-3 text-amber-300 max-w-xs truncate">${inc.rule_violated.split(':')[0]}</td>
        <td class="py-2 px-3 whitespace-nowrap">
          ${hasMitigation ? `
            <span class="px-2 py-0.5 rounded border text-[9px] font-mono ${inc.mitigation.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-purple-950 text-purple-300 border-purple-800'}">
              <i class="fa-solid fa-wand-magic-sparkles mr-1"></i> ${inc.mitigation.status}
            </span>
          ` : `
            <span class="text-slate-500">${inc.remediation_taken.split(':')[0]}</span>
          `}
        </td>
        <td class="py-2 px-3 text-right whitespace-nowrap">
          <button onclick="event.stopPropagation(); openIncidentDetailsModal('${inc.incident_id}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-[10px] transition">
            <i class="fa-solid fa-magnifying-glass"></i> Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function filterEventHistory() {
  renderEventHistory(currentIncidents);
}

function selectIncident(incidentId) {
  selectedIncidentId = incidentId;
  const inc = currentIncidents.find(i => i.incident_id === incidentId);
  if (inc) {
    renderTrace(inc);
    renderIncidents(currentIncidents);
  }
}

function renderTrace(inc) {
  const container = document.getElementById("trace-details");
  if (!container) return;

  const traceJson = JSON.stringify(inc.technical_trace, null, 2);

  container.innerHTML = `
    <div class="space-y-1.5 bg-slate-950/70 p-2.5 rounded-xl border border-slate-800">
      <div class="flex items-center justify-between border-b border-slate-800 pb-1">
        <div class="font-bold text-rose-400 flex items-center gap-1.5 text-xs">
          <i class="fa-solid fa-crosshairs"></i> ${inc.incident_id}: ${inc.category}
        </div>
        <button onclick="openIncidentDetailsModal('${inc.incident_id}')" class="text-cyan-400 hover:text-cyan-300 text-[10px] font-mono flex items-center gap-1">
          Full Modal &rarr;
        </button>
      </div>

      <div class="grid grid-cols-2 gap-1 text-[9.5px] bg-slate-900/60 p-1.5 rounded-lg border border-slate-800">
        <div><span class="text-slate-500">Agent:</span> <span class="text-cyan-400 font-bold">${inc.agent_name}</span></div>
        <div><span class="text-slate-500">Namespace:</span> <span class="text-slate-300 font-bold">${inc.namespace}</span></div>
      </div>

      <div>
        <div class="text-slate-400 font-semibold text-[9px]">Policy Violated:</div>
        <div class="text-amber-400 bg-amber-950/30 border border-amber-900/50 p-1 rounded text-[9.5px]">
          ${inc.rule_violated}
        </div>
      </div>

      <div>
        <div class="text-slate-400 font-semibold text-[9px]">Remediation Enforced:</div>
        <div class="text-emerald-400 bg-emerald-950/30 border border-emerald-900/50 p-1 rounded text-[9.5px] font-bold">
          <i class="fa-solid fa-shield-virus mr-1"></i> ${inc.remediation_taken}
        </div>
      </div>

      <div>
        <div class="text-slate-400 font-semibold text-[9px]">Captured Trace Snippet:</div>
        <pre class="bg-black/80 text-emerald-300 p-1.5 rounded-lg border border-slate-800 text-[9px] overflow-x-auto scrollbar-thin max-h-16">${escapeHtml(traceJson)}</pre>
      </div>
    </div>
  `;
}

function openIncidentDetailsModal(incidentId) {
  const inc = currentIncidents.find(i => i.incident_id === incidentId);
  if (!inc) return;

  document.getElementById("modal-incident-id").innerText = inc.incident_id;
  document.getElementById("modal-incident-title").innerText = inc.title;

  const sevBadge = document.getElementById("modal-incident-severity");
  sevBadge.innerText = inc.severity;
  if (inc.severity === "CRITICAL") {
    sevBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800";
    document.getElementById("modal-incident-icon").className = "w-9 h-9 rounded-xl bg-rose-950 border border-rose-800 text-rose-400 flex items-center justify-center text-sm";
  } else {
    sevBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-950 text-amber-300 border border-amber-800";
    document.getElementById("modal-incident-icon").className = "w-9 h-9 rounded-xl bg-amber-950 border border-amber-800 text-amber-400 flex items-center justify-center text-sm";
  }

  const modalBody = document.getElementById("modal-incident-body");
  const traceFormatted = JSON.stringify(inc.technical_trace, null, 2);

  modalBody.innerHTML = `
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800">
      <div>
        <span class="text-slate-500 block text-[10px] uppercase">Incident Timestamp</span>
        <span class="text-slate-200 font-bold">${new Date(inc.timestamp * 1000).toLocaleString()}</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[10px] uppercase">Violation Category</span>
        <span class="text-cyan-400 font-bold">${inc.category}</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[10px] uppercase">Target Agent</span>
        <span class="text-white font-bold">${inc.agent_name} (${inc.agent_id})</span>
      </div>
      <div>
        <span class="text-slate-500 block text-[10px] uppercase">Kubernetes Namespace</span>
        <span class="text-indigo-400 font-bold">${inc.namespace}</span>
      </div>
    </div>

    <div class="bg-slate-900/70 p-3 rounded-xl border border-slate-800">
      <div class="text-slate-300 font-bold mb-1 flex items-center gap-1.5">
        <i class="fa-solid fa-cube text-cyan-400"></i> Attribution to Kubernetes Pod:
      </div>
      <div class="text-slate-200 font-mono text-xs bg-slate-950 p-2 rounded border border-slate-800 break-all">
        ${inc.pod_name}
      </div>
    </div>

    <div class="space-y-2">
      <div>
        <span class="text-slate-400 font-semibold block mb-1">Threat Description:</span>
        <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300 leading-relaxed">
          ${inc.description}
        </div>
      </div>

      <div>
        <span class="text-slate-400 font-semibold block mb-1">Security Guardrail / Policy Violated:</span>
        <div class="bg-rose-950/30 p-2.5 rounded-lg border border-rose-900/60 text-rose-300 font-bold">
          <i class="fa-solid fa-triangle-exclamation mr-1.5 text-rose-400"></i> ${inc.rule_violated}
        </div>
      </div>

      <div>
        <span class="text-slate-400 font-semibold block mb-1">SuperK8Security Autonomous Remediation Action:</span>
        <div class="bg-emerald-950/30 p-2.5 rounded-lg border border-emerald-900/60 text-emerald-300 font-bold">
          <i class="fa-solid fa-shield-virus mr-1.5 text-emerald-400"></i> ${inc.remediation_taken}
        </div>
      </div>
    </div>

    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-slate-400 font-semibold">Deep Technical Trace &amp; Intercepted Payload:</span>
        <span class="text-slate-500 text-[10px]">Tamper-Proof Audit Evidence</span>
      </div>
      <pre class="bg-black/90 text-emerald-400 p-3 rounded-xl border border-slate-800 text-[11px] overflow-x-auto scrollbar-thin max-h-48 leading-relaxed">${escapeHtml(traceFormatted)}</pre>
    </div>
  `;

  document.getElementById("incident-modal").classList.remove("hidden");
}

function closeIncidentModal() {
  document.getElementById("incident-modal").classList.add("hidden");
}

function openPodModal(podName) {
  const pod = currentPods.find(p => p.pod_name === podName);
  if (!pod) return;

  document.getElementById("modal-pod-name").innerText = pod.pod_name;
  document.getElementById("modal-agent-name").innerText = `${pod.agent_name} (${pod.manifest.role})`;

  const content = document.getElementById("modal-content");
  content.innerHTML = `
    <div class="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800">
      <div><span class="text-slate-500">Namespace:</span> <span class="text-cyan-400 font-bold">${pod.namespace}</span></div>
      <div><span class="text-slate-500">Status:</span> <span class="${pod.quarantined ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${pod.status}</span></div>
      <div><span class="text-slate-500">Pod IP:</span> <span class="text-slate-200">${pod.ip}</span></div>
      <div><span class="text-slate-500">Cluster Node:</span> <span class="text-slate-200">${pod.node}</span></div>
      <div><span class="text-slate-500">Security Score:</span> <span class="${pod.security_score < 70 ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${pod.security_score}/100</span></div>
      <div><span class="text-slate-500">Active Sockets:</span> <span class="text-slate-200">${pod.active_connections}</span></div>
    </div>

    <div>
      <div class="text-slate-300 font-semibold mb-1 flex items-center gap-1.5">
        <i class="fa-solid fa-network-wired text-cyan-400"></i> Strict Egress Network Allowlist ("Only See What They See"):
      </div>
      <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300">
        ${pod.manifest.allowed_egress_destinations.map(d => `<div class="py-0.5 text-emerald-400"><i class="fa-solid fa-check text-xs mr-1 text-emerald-500"></i> ${d}</div>`).join('')}
      </div>
    </div>

    <div>
      <div class="text-slate-300 font-semibold mb-1 flex items-center gap-1.5">
        <i class="fa-solid fa-key text-purple-400"></i> Kubernetes RBAC API Scope:
      </div>
      <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300">
        ${pod.manifest.allowed_k8s_api_verbs.length > 0 ? 
          pod.manifest.allowed_k8s_api_verbs.map(v => `<span class="inline-block mr-2 px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono text-[10px]">verb: ${v}</span>`).join('') 
          : '<span class="text-slate-500 italic">None (Pod has ZERO Kubernetes API authorization)</span>'}
      </div>
    </div>

    <div>
      <div class="text-slate-300 font-semibold mb-1 flex items-center gap-1.5">
        <i class="fa-solid fa-folder-closed text-amber-400"></i> Sandboxed Filesystem Bounds:
      </div>
      <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300">
        ${pod.manifest.allowed_filesystem_paths.map(p => `<div class="py-0.5 text-cyan-300"><i class="fa-solid fa-folder-tree text-xs mr-1 text-cyan-500"></i> ${p}</div>`).join('')}
      </div>
    </div>
  `;

  document.getElementById("pod-modal").classList.remove("hidden");
}

function closePodModal() {
  document.getElementById("pod-modal").classList.add("hidden");
}

async function resetCluster() {
  try {
    await fetch('/api/simulate/attack/reset', { method: 'POST' });
    selectedIncidentId = null;
    document.getElementById("trace-details").innerHTML = `
      <div class="text-slate-500 text-center py-6 italic text-[10.5px]">
        Select any incident or mitigation to trace the origin pod, agent identity, exact payload/syscall, and remediation action.
      </div>
    `;
  } catch (e) {
    console.error("Failed to reset cluster:", e);
  }
}

function exportAuditLog() {
  const blob = new Blob([JSON.stringify(currentIncidents, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `superk8security_audit_log_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

window.addEventListener("DOMContentLoaded", () => {
  initWebSocket();
});
