# Clean pure SVG generator for Slide 2 Architecture Diagram
svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1100 620" class="w-full h-auto max-h-[460px]">
  <defs>
    <linearGradient id="gradExternal" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.8"/>
      <stop offset="100%" stop-color="#0f172a" stop-opacity="0.9"/>
    </linearGradient>
    <linearGradient id="gradCluster" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b1329" stop-opacity="0.95"/>
      <stop offset="100%" stop-color="#030712" stop-opacity="0.98"/>
    </linearGradient>
    <linearGradient id="gradIngress" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#065f46"/>
      <stop offset="100%" stop-color="#047857"/>
    </linearGradient>
    <linearGradient id="gradEgress" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#991b1b"/>
      <stop offset="100%" stop-color="#b91c1c"/>
    </linearGradient>
    <linearGradient id="gradSoc" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#075985"/>
      <stop offset="100%" stop-color="#0369a1"/>
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- CLUSTER OUTER BOUNDARY -->
  <rect x="230" y="20" width="850" height="580" rx="18" fill="url(#gradCluster)" stroke="#1e293b" stroke-width="2.5"/>
  <text x="255" y="52" fill="#38bdf8" font-family="monospace" font-size="14" font-weight="bold" letter-spacing="1">KUBERNETES CLUSTER BOUNDARY (Virtual Multi-Tenant AI Platform)</text>

  <!-- EXTERNAL UNTRUSTED ZONE (LEFT) -->
  <rect x="20" y="20" width="180" height="580" rx="16" fill="url(#gradExternal)" stroke="#312e81" stroke-width="2"/>
  <text x="35" y="52" fill="#a5b4fc" font-family="monospace" font-size="12" font-weight="bold">EXTERNAL UNTRUSTED</text>

  <!-- External Entities -->
  <rect x="35" y="80" width="150" height="70" rx="10" fill="#1e1b4b" stroke="#4338ca" stroke-width="1.5"/>
  <text x="50" y="110" fill="#e0e7ff" font-family="sans-serif" font-size="12" font-weight="bold">Ingress Users</text>
  <text x="50" y="130" fill="#94a3b8" font-family="sans-serif" font-size="10">Webhooks / API Calls</text>

  <rect x="35" y="250" width="150" height="85" rx="10" fill="#311020" stroke="#9f1239" stroke-width="1.5"/>
  <text x="45" y="278" fill="#fda4af" font-family="sans-serif" font-size="11" font-weight="bold">Public Internet APIs</text>
  <text x="45" y="298" fill="#e2e8f0" font-family="monospace" font-size="10">api.openai.com</text>
  <text x="45" y="318" fill="#fb7185" font-family="sans-serif" font-size="10 font-weight="bold">[UNAUTHORIZED]</text>

  <rect x="35" y="420" width="150" height="80" rx="10" fill="#450a0a" stroke="#dc2626" stroke-width="1.5"/>
  <text x="45" y="448" fill="#fca5a5" font-family="sans-serif" font-size="11" font-weight="bold">C2 Exfil Servers</text>
  <text x="45" y="468" fill="#e2e8f0" font-family="monospace" font-size="10">198.51.100.42</text>
  <text x="45" y="488" fill="#ef4444" font-family="sans-serif" font-size="10" font-weight="bold">[MALICIOUS IP]</text>

  <!-- LAYER 1: INGRESS GATEWAY & DPI GUARD -->
  <rect x="255" y="80" width="220" height="110" rx="12" fill="#064e3b" stroke="#10b981" stroke-width="1.5"/>
  <text x="270" y="105" fill="#a7f3d0" font-family="sans-serif" font-size="12" font-weight="bold">Ingress Gateway &amp; DPI Guard</text>
  <text x="270" y="125" fill="#e2e8f0" font-family="sans-serif" font-size="10">- Inbound Payload Inspection</text>
  <text x="270" y="142" fill="#e2e8f0" font-family="sans-serif" font-size="10">- Prompt Injection Blocker</text>
  <text x="270" y="160" fill="#6ee7b7" font-family="monospace" font-size="9">RULE: POLICY-INGRESS-004</text>
  <text x="270" y="177" fill="#34d399" font-family="sans-serif" font-size="10" font-weight="bold">STATUS: ACTIVE BLOCK</text>

  <!-- LAYER 2: WORKLOAD AGENT PODS (CENTER) -->
  <rect x="510" y="80" width="310" height="495" rx="14" fill="#0f172a" stroke="#334155" stroke-width="2"/>
  <text x="525" y="105" fill="#f8fafc" font-family="sans-serif" font-size="13" font-weight="bold">10 Sandboxed Agent Workload Pods</text>
  <text x="525" y="122" fill="#94a3b8" font-family="monospace" font-size="10">Least-Privilege RBAC &amp; Network Isolated</text>

  <!-- Pod 1 -->
  <rect x="525" y="135" width="280" height="50" rx="8" fill="#1e293b" stroke="#0284c7" stroke-width="1"/>
  <text x="535" y="155" fill="#38bdf8" font-family="sans-serif" font-size="11" font-weight="bold">pod-customer-support</text>
  <text x="535" y="172" fill="#94a3b8" font-family="monospace" font-size="9">ns: crm | Ingress Gateway authorized</text>

  <!-- Pod 2 -->
  <rect x="525" y="195" width="280" height="50" rx="8" fill="#1e293b" stroke="#3b82f6" stroke-width="1"/>
  <text x="535" y="215" fill="#60a5fa" font-family="sans-serif" font-size="11" font-weight="bold">pod-code-reviewer</text>
  <text x="535" y="232" fill="#94a3b8" font-family="monospace" font-size="9">ns: devops | Git &amp; Sonar scope only</text>

  <!-- Pod 3 -->
  <rect x="525" y="255" width="280" height="50" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1"/>
  <text x="535" y="275" fill="#c084fc" font-family="sans-serif" font-size="11" font-weight="bold">pod-billing-calc</text>
  <text x="535" y="292" fill="#f43f5e" font-family="monospace" font-size="9">ns: finance | ZERO K8s API PRIVILEGE</text>

  <!-- Pod 4 -->
  <rect x="525" y="315" width="280" height="58" rx="8" fill="#2d1217" stroke="#e11d48" stroke-width="1.5"/>
  <text x="535" y="335" fill="#fb7185" font-family="sans-serif" font-size="11" font-weight="bold">pod-data-analyzer (ATTACK TARGET)</text>
  <text x="535" y="352" fill="#fecdd3" font-family="monospace" font-size="9">ns: analytics | Attempted Internet Egress</text>
  <text x="535" y="366" fill="#f43f5e" font-family="sans-serif" font-size="9" font-weight="bold">QUARANTINED VIA NETWORKPOLICY</text>

  <!-- Pods 5-10 Group -->
  <rect x="525" y="385" width="280" height="175" rx="8" fill="#090d16" stroke="#1f2937" stroke-width="1"/>
  <text x="535" y="405" fill="#cbd5e1" font-family="sans-serif" font-size="11" font-weight="bold">Pods 5 - 10 (Strict Sandbox Enforced):</text>
  <text x="535" y="425" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-search-indexer (ns: search)</text>
  <text x="535" y="443" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-auth-sync (ns: identity)</text>
  <text x="535" y="461" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-doc-summarizer (ns: docs)</text>
  <text x="535" y="479" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-lead-scorer (ns: marketing)</text>
  <text x="535" y="497" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-inventory-tracker (ns: supply-chain)</text>
  <text x="535" y="515" fill="#94a3b8" font-family="monospace" font-size="9.5">- pod-compliance-checker (ns: audit)</text>
  <text x="535" y="542" fill="#38bdf8" font-family="sans-serif" font-size="10" font-weight="bold">&#10004; Inter-Agent A2A Isolation Enforced</text>

  <!-- LAYER 3: EGRESS SHIELD (RIGHT TOP) -->
  <rect x="850" y="80" width="210" height="230" rx="12" fill="#450a0a" stroke="#dc2626" stroke-width="2"/>
  <text x="865" y="108" fill="#fca5a5" font-family="sans-serif" font-size="12" font-weight="bold">Egress Threat Shield</text>
  <text x="865" y="130" fill="#fecaca" font-family="monospace" font-size="9.5">POLICY-NET-ZERO-EGRESS</text>
  <text x="865" y="150" fill="#e2e8f0" font-family="sans-serif" font-size="10">- Zero-Trust External Deny</text>
  <text x="865" y="168" fill="#e2e8f0" font-family="sans-serif" font-size="10">- DNS Egress Filtering</text>
  <text x="865" y="186" fill="#e2e8f0" font-family="sans-serif" font-size="10">- IP Reputation / C2 Drops</text>
  <text x="865" y="208" fill="#ef4444" font-family="sans-serif" font-size="11" font-weight="bold">SEVER TCP SOCKET (RST)</text>
  <rect x="865" y="225" width="180" height="65" rx="6" fill="#1f1315" stroke="#7f1d1d" stroke-width="1"/>
  <text x="875" y="245" fill="#fca5a5" font-family="sans-serif" font-size="9.5" font-weight="bold">Automated Quarantine:</text>
  <text x="875" y="262" fill="#f87171" font-family="monospace" font-size="9">Cilium Default-Deny</text>
  <text x="875" y="278" fill="#f87171" font-family="monospace" font-size="9">Token Invalidated</text>

  <!-- LAYER 4: SUPERK8SECURITY CONTROL PLANE & SOC (RIGHT BOTTOM) -->
  <rect x="850" y="335" width="210" height="240" rx="12" fill="url(#gradSoc)" stroke="#38bdf8" stroke-width="2"/>
  <text x="865" y="362" fill="#ffffff" font-family="sans-serif" font-size="12" font-weight="bold">SuperK8Security Control</text>
  <text x="865" y="380" fill="#bae6fd" font-family="monospace" font-size="9.5">AI Security Agent &amp; SOC</text>
  <text x="865" y="405" fill="#f0f9ff" font-family="sans-serif" font-size="10">- eBPF Syscall Monitor</text>
  <text x="865" y="423" fill="#f0f9ff" font-family="sans-serif" font-size="10">- Real-Time Policy Engine</text>
  <text x="865" y="441" fill="#f0f9ff" font-family="sans-serif" font-size="10">- Sub-ms Autonomous Actions</text>
  <text x="865" y="465" fill="#f0f9ff" font-family="sans-serif" font-size="10" font-weight="bold">Incident Tracer (WebSocket):</text>
  <text x="865" y="483" fill="#38bdf8" font-family="monospace" font-size="9">&#9658; Traced to Pod UID</text>
  <text x="865" y="499" fill="#38bdf8" font-family="monospace" font-size="9">&#9658; Traced to Agent ID</text>
  <text x="865" y="515" fill="#38bdf8" font-family="monospace" font-size="9">&#9658; Raw Payload Captured</text>
  <text x="865" y="545" fill="#67e8f9" font-family="sans-serif" font-size="11" font-weight="bold">&#10004; ACTIVE ON :8000</text>

  <!-- CONNECTOR ARROWS & FLOWS -->
  <!-- 1. Ingress Flow -->
  <path d="M 185 115 L 255 115" stroke="#34d399" stroke-width="2.5" marker-end="url(#arrow)" fill="none"/>
  <path d="M 475 140 L 525 140" stroke="#34d399" stroke-width="2.5" fill="none"/>
  <text x="200" y="105" fill="#34d399" font-family="monospace" font-size="9">HTTPS</text>

  <!-- 2. Blocked Egress Flow -->
  <path d="M 805 340 L 850 200" stroke="#f43f5e" stroke-width="2.5" stroke-dasharray="5,5" fill="none"/>
  <text x="810" y="250" fill="#f43f5e" font-family="monospace" font-size="9">BLOCKED</text>

  <!-- 3. Denied Egress to External -->
  <path d="M 850 150 L 185 285" stroke="#ef4444" stroke-width="2" stroke-dasharray="4,4" fill="none"/>
  <path d="M 850 170 L 185 450" stroke="#ef4444" stroke-width="2" stroke-dasharray="4,4" fill="none"/>
  <text x="320" y="270" fill="#ef4444" font-family="sans-serif" font-size="11" font-weight="bold">&#10008; OUTBOUND DENIED BY EGRESS SHIELD</text>

  <!-- 4. Telemetry to SOC -->
  <path d="M 750 373 L 850 420" stroke="#38bdf8" stroke-width="2" stroke-dasharray="3,3" fill="none"/>
  <path d="M 365 190 L 850 460" stroke="#38bdf8" stroke-width="1.5" stroke-dasharray="3,3" fill="none"/>
</svg>
"""

with open('/config/Desktop/Session1/superk8security/slides/assets/architecture.svg', 'w') as f:
    f.write(svg_content)
print("SVG architecture diagram successfully generated at slides/assets/architecture.svg")
