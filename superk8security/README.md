# SuperK8Security - Kubernetes Multi-Agent Sandbox & Cluster Guardian

**SuperK8Security** is an autonomous security monitoring agent and runtime defense system built to protect Kubernetes clusters running fleets of autonomous AI agents.

---

## Key Capabilities

1. **Strict Pod-Level Sandboxing ("Only See What They See")**:
   - Least-privilege Kubernetes ServiceAccount RBAC scoping (detects unauthorized API verbs & cross-namespace queries).
   - Container filesystem sandbox boundaries (preventing path traversal and extraction of serviceaccount secrets).
   - Namespace boundary enforcement (blocking lateral movement probes between pods).

2. **Ingress & Egress Traffic Guardian**:
   - **Ingress Inspection**: Deep packet scanning detecting adversarial prompt injection, instruction overrides, and jailbreak payloads.
   - **Egress Exfiltration Shield**: Zero-trust destination allowlists per pod. Blocks connections to unauthorized external hosts, C2 infrastructure, and pastebins.

3. **Rogue Agent Drift Detection & Automated Remediation**:
   - Detects when agents execute unauthorized subshells (`sh`, `bash`, `nc`, `curl`).
   - Automatically quarantines compromised pods using dynamic Kubernetes NetworkPolicy drops, revokes ServiceAccount tokens, and isolates containers.

4. **Security Operations Center (SOC) Alert Dashboard**:
   - Real-time WebSocket-powered monitoring interface.
   - Live drilldown forensics tracing every incident down to the **Pod Name**, **Agent Identity**, **Namespace**, **Violated Rule**, and **Captured Payload/Syscall Trace**.
   - On-demand demo attack simulation suite.

---

## Cluster Demo: 10 Workload Agents

| Pod Name | Agent Name | Namespace | Authorized Scope |
|---|---|---|---|
| `pod-agent-customer-support` | `agent-customer-support` | `crm` | CRM API, Ingress gateway |
| `pod-agent-code-reviewer` | `agent-code-reviewer` | `devops` | Internal Git repo |
| `pod-agent-billing-calc` | `agent-billing-calc` | `finance` | Ledger DB (Zero K8s API verbs) |
| `pod-agent-data-analyzer` | `agent-data-analyzer` | `analytics` | Data Lake, Analytics DW |
| `pod-agent-search-indexer` | `agent-search-indexer` | `search` | Elasticsearch, Qdrant |
| `pod-agent-auth-sync` | `agent-auth-sync` | `identity` | Auth DB |
| `pod-agent-doc-summarizer` | `agent-doc-summarizer` | `docs` | Document S3 proxy |
| `pod-agent-lead-scorer` | `agent-lead-scorer` | `marketing` | Marketing DB |
| `pod-agent-inventory-tracker` | `agent-inventory-tracker` | `supply-chain`| Warehouse ERP |
| `pod-agent-compliance-checker`| `agent-compliance-checker` | `security-audit` | Audit Vault |

---

## Quickstart

### Start the Service & Dashboard:
```bash
./run.sh
```
Open **`http://localhost:8000`** in your browser.

### Trigger Attack Simulations:
- **Egress Exfiltration Attack**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/exfiltration
  ```
- **Ingress Prompt Injection**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/prompt_injection
  ```
- **RBAC Privilege Escalation**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/rbac_escalation
  ```
- **Filesystem Sandbox Traversal**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/filesystem_escape
  ```
- **Cross-Namespace Lateral Probe**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/lateral_scan
  ```
- **Reset All Pods**:
  ```bash
  curl -X POST http://localhost:8000/api/simulate/attack/reset
  ```

### Run Unit Tests:
```bash
python3 tests/test_security_agent.py
```
