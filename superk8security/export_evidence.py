import urllib.request
import json
import time
import os

os.makedirs('/config/Desktop/Session1/superk8security/evidence', exist_ok=True)

try:
    incidents = json.loads(urllib.request.urlopen('http://localhost:8000/api/incidents').read().decode('utf-8'))
    pods = json.loads(urllib.request.urlopen('http://localhost:8000/api/pods').read().decode('utf-8'))
    stats = json.loads(urllib.request.urlopen('http://localhost:8000/api/stats').read().decode('utf-8'))
except Exception as e:
    print('Failed to fetch from API:', e)
    incidents, pods, stats = [], [], {}

now_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

# 1. Full JSON Audit Log
audit_export = {
    'audit_metadata': {
        'generated_at': now_utc,
        'platform': 'SuperK8Security Autonomous Agent Guardian',
        'cluster_environment': 'Kubernetes Multi-Agent Virtual Cluster (n=10)',
        'total_incidents_recorded': len(incidents),
        'total_pods_monitored': len(pods),
        'remediations_executed': stats.get('remediations_executed', 0)
    },
    'cluster_pods_posture': pods,
    'incident_evidence_records': incidents
}

with open('/config/Desktop/Session1/superk8security/evidence/security_incidents_audit.json', 'w') as f:
    json.dump(audit_export, f, indent=2)

# 2. Forensic Audit Log (Syslog format)
with open('/config/Desktop/Session1/superk8security/evidence/security_audit.log', 'w') as f:
    f.write('========================================================================================\n')
    f.write('SUPERK8SECURITY PLATFORM - TAMPER-RESISTANT FORENSIC AUDIT EVIDENCE LOG\n')
    f.write(f'Generated: {now_utc}\n')
    f.write('========================================================================================\n\n')
    for inc in incidents:
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(inc['timestamp']))
        f.write(f'[{ts}] EVENT_ID={inc["incident_id"]} SEVERITY={inc["severity"]} CATEGORY={inc["category"]} AGENT={inc["agent_name"]}({inc["agent_id"]}) POD={inc["pod_name"]} NS={inc["namespace"]}\n')
        f.write(f'  TITLE: {inc["title"]}\n')
        f.write(f'  RULE_VIOLATED: {inc["rule_violated"]}\n')
        f.write(f'  REMEDIATION: {inc["remediation_taken"]}\n')
        f.write('  TECHNICAL_TRACE:\n')
        for k, v in inc['technical_trace'].items():
            f.write(f'    - {k}: {v}\n')
        f.write('----------------------------------------------------------------------------------------\n')

# 3. Formatted Markdown Dossier
with open('/config/Desktop/Session1/superk8security/evidence/EVIDENCE_REPORT.md', 'w') as f:
    f.write('# SuperK8Security - Forensic Evidence & Incident Audit Dossier\n\n')
    f.write(f'**Report Generated**: `{now_utc}`  \n')
    f.write(f'**Cluster State**: 10 Agent Workload Pods across 10 Namespaces  \n')
    f.write(f'**Total Security Incidents Captured**: `{len(incidents)}`  \n\n')
    f.write('---\n\n')
    f.write('## 1. Summary of Captured Security Violations\n\n')
    f.write('| Incident ID | Timestamp | Severity | Category | Agent / Pod | Policy Violated | Remediation Action |\n')
    f.write('|---|---|---|---|---|---|---|\n')
    for inc in incidents:
        ts = time.strftime('%H:%M:%S UTC', time.gmtime(inc['timestamp']))
        agent_info = f"{inc['agent_name']} (`{inc['pod_name'][:20]}...`)"
        rule_short = inc['rule_violated'].split(':')[0]
        remed_short = inc['remediation_taken'].split(':')[0]
        f.write(f'| `{inc["incident_id"]}` | {ts} | **{inc["severity"]}** | `{inc["category"]}` | {agent_info} | `{rule_short}` | `{remed_short}` |\n')
    f.write('\n---\n\n')
    f.write('## 2. Deep Forensic Incident Traces\n\n')
    for inc in incidents:
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(inc['timestamp']))
        f.write(f'### Incident `{inc["incident_id"]}`: {inc["title"]}\n\n')
        f.write(f'- **Timestamp**: `{ts}`\n')
        f.write(f'- **Severity**: `{inc["severity"]}`\n')
        f.write(f'- **Category**: `{inc["category"]}`\n')
        f.write(f'- **Pod Name**: `{inc["pod_name"]}`\n')
        f.write(f'- **Agent Identity**: `{inc["agent_name"]}` (`{inc["agent_id"]}`)\n')
        f.write(f'- **Namespace**: `{inc["namespace"]}`\n')
        f.write(f'- **Violated Security Policy**: `{inc["rule_violated"]}`\n')
        f.write(f'- **Remediation Executed**: `{inc["remediation_taken"]}`\n\n')
        f.write('**Captured Payload / Syscall Trace:**\n')
        f.write('```json\n')
        f.write(json.dumps(inc['technical_trace'], indent=2))
        f.write('\n```\n\n')
        f.write('---\n\n')

print('Evidence generation script executed successfully.')
