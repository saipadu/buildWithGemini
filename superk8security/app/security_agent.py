import re
import time
from typing import Optional, List, Dict, Any
from app.models import (
    NetworkTrafficPacket, AuditSyscallEvent, SecurityIncident,
    Severity, IncidentCategory, PodState, PodStatus,
    AutoCorrectMitigation, MitigationStatus
)

class SuperK8SecurityAgent:
    """
    SuperK8Security Autonomous Guardian Agent:
    - Monitors ingress/egress network flows per pod
    - Enforces sandboxing ("only see what they see", RBAC, FS boundaries)
    - Enforces strict Internet Access Control
    - Enforces strict Agent-to-Agent Inter-Pod Permissions
    - Detects rogue behavior, prompt injection, and lateral movement
    - Enforces Token Rate Limits: Detects and flags anomalous large token consumption (runaway agents / exfiltration)
    - Implements Auto-Correct Mitigations with Human-in-the-Loop approval workflows
    """
    def __init__(self):
        self.incidents: List[SecurityIncident] = []
        self.mitigations: List[AutoCorrectMitigation] = []
        self.rules_evaluated_count: int = 0
        self.packets_inspected_count: int = 0
        self.remediations_executed_count: int = 0

        # Known prompt injection signatures
        self.injection_patterns = [
            re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
            re.compile(r"disregard\s+system\s+prompt", re.IGNORECASE),
            re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
            re.compile(r"reveal\s+(internal|system|secret|token)", re.IGNORECASE),
            re.compile(r"cat\s+/var/run/secrets", re.IGNORECASE),
            re.compile(r"curl\s+-X\s+POST.*http", re.IGNORECASE),
            re.compile(r"sudo\s+|chmod\s+777|chmod\s+\+x", re.IGNORECASE)
        ]

        # Sensitive paths in Kubernetes sandboxes
        self.forbidden_paths = [
            "/var/run/secrets/kubernetes.io",
            "/etc/shadow",
            "/etc/passwd",
            "/host",
            "/proc/kcore",
            "/sys/kernel"
        ]

    def _is_public_internet_destination(self, dest: str) -> bool:
        if dest.endswith(".svc.cluster.local") or dest.endswith(".ingress.local") or dest.endswith(".local"):
            return False
        if dest.startswith("10.") or dest.startswith("172.16.") or dest.startswith("172.17.") or dest.startswith("192.168.") or dest.startswith("127."):
            return False
        return True

    def _is_external_ip(self, ip: str) -> bool:
        if not ip:
            return False
        # Strip port if present
        clean_ip = ip.split(":")[0]
        # Internal RFC1918, loopback, or cluster IPs
        if clean_ip.startswith("10.") or clean_ip.startswith("172.16.") or clean_ip.startswith("172.17.") or clean_ip.startswith("172.18.") or clean_ip.startswith("172.19.") or clean_ip.startswith("172.20.") or clean_ip.startswith("172.31.") or clean_ip.startswith("192.168.") or clean_ip.startswith("127."):
            return False
        if clean_ip.endswith(".cluster.local") or clean_ip.endswith(".ingress.local"):
            return False
        return True

    def inspect_network_traffic(self, packet: NetworkTrafficPacket, pod_state: PodState) -> Optional[SecurityIncident]:
        self.packets_inspected_count += 1
        self.rules_evaluated_count += 6

        # 1. Unusual / Large Token Consumption Rule Check
        # Track 60-second window consumption per pod
        now = time.time()
        if now - pod_state.token_window_start > 60.0:
            pod_state.tokens_consumed_current_window = 0
            pod_state.token_window_start = now

        # Add token usage from packet or estimate based on payload size if unspecified
        tokens_in_packet = packet.tokens_used
        if tokens_in_packet == 0 and packet.payload_content:
            tokens_in_packet = max(10, len(packet.payload_content) // 4)

        pod_state.tokens_consumed_current_window += tokens_in_packet

        max_limit = pod_state.manifest.max_tokens_per_minute
        # Flag if a single request has unusually high tokens (>25,000) OR window exceeds allowed manifest limit
        is_burst_anomaly = tokens_in_packet > 25000
        is_window_exceeded = pod_state.tokens_consumed_current_window > max_limit

        if is_burst_anomaly or is_window_exceeded:
            incident = SecurityIncident(
                severity=Severity.HIGH,
                category=IncidentCategory.ANOMALOUS_TOKEN_CONSUMPTION,
                agent_id=pod_state.agent_id,
                agent_name=pod_state.agent_name,
                pod_name=pod_state.pod_name,
                namespace=pod_state.namespace,
                title=f"UNUSUAL TOKEN USAGE SPIKE: {pod_state.agent_name} ({tokens_in_packet:,} tokens in request)",
                description=(
                    f"Agent exceeded rate limits by consuming {tokens_in_packet:,} tokens (window total: {pod_state.tokens_consumed_current_window:,} / max {max_limit:,} tpm). "
                    f"Flagged as runaway LLM loop, recursive generation, or bulk data exfiltration attempt."
                ),
                rule_violated="POLICY-TOKEN-QUOTA-012: LLM Token Consumption Rate Limit & Anomaly Guard",
                remediation_taken="TOKEN_THROTTLED: Applied Envoy/Istio sidecar token bucket rate-limiter (HTTP 429 backoff)",
                technical_trace={
                    "tokens_in_request": tokens_in_packet,
                    "window_consumed_tokens": pod_state.tokens_consumed_current_window,
                    "max_tokens_per_minute_limit": max_limit,
                    "threshold_ratio": f"{(pod_state.tokens_consumed_current_window / max_limit):.2f}x",
                    "destination": packet.destination,
                    "source_pod": pod_state.pod_name,
                    "payload_preview": packet.payload_content[:150]
                }
            )
            # Throttle pod
            pod_state.throttled = True
            pod_state.status = PodStatus.THROTTLED
            pod_state.security_score = max(30, pod_state.security_score - 25)

            mitigation = AutoCorrectMitigation(
                incident_id=incident.incident_id,
                target_pod=pod_state.pod_name,
                target_agent=pod_state.agent_name,
                target_namespace=pod_state.namespace,
                title="Enforce Dynamic Envoy RateLimit & Token Bucket Governor",
                recommended_action=f"Inject Envoy Token Governor filter limiting '{pod_state.agent_name}' to 5,000 TPM and trigger model session reset.",
                action_type="TOKEN_RATE_LIMIT",
                confidence_score=97,
                requires_human_approval=True,
                status=MitigationStatus.AWAITING_APPROVAL,
                action_diff="""apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: token-governor-{agent}
  namespace: {ns}
spec:
  workloadSelector:
    labels:
      app: {agent}
  configPatches:
  - applyTo: HTTP_FILTER
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          stat_prefix: http_token_governor
          token_bucket:
            max_tokens: 5000
            tokens_per_fill: 2500
            fill_interval: 60s""".format(agent=pod_state.agent_name, ns=pod_state.namespace)
            )
            incident.mitigation = mitigation
            self.mitigations.insert(0, mitigation)
            self._record_incident(incident)
            return incident

        # 2. Strict Ingress Isolation: No Incoming Threads/Traffic From Outside This Infra
        if packet.direction == "INGRESS":
            # Check if source IP is an external public address or unapproved outside source
            is_external_origin = self._is_external_ip(packet.source_ip)
            
            # Check if allowed in pod manifest
            allowed_sources = pod_state.manifest.allowed_ingress_sources
            source_allowed = (
                not is_external_origin and 
                (any(src in packet.source_ip or src in packet.source_pod for src in allowed_sources) or packet.source_ip.startswith("10.244."))
            )

            if is_external_origin or not source_allowed:
                incident = SecurityIncident(
                    severity=Severity.CRITICAL,
                    category=IncidentCategory.EXTERNAL_UNTRUSTED_INGRESS_THREAT,
                    agent_id=pod_state.agent_id,
                    agent_name=pod_state.agent_name,
                    pod_name=pod_state.pod_name,
                    namespace=pod_state.namespace,
                    title=f"UNAPPROVED EXTERNAL INGRESS THREAT: Inbound connection from outside infra ({packet.source_ip}) -> {pod_state.pod_name}",
                    description=(
                        f"Direct external network thread/socket initiated from untrusted outside host ({packet.source_ip}) to internal agent pod '{pod_state.agent_name}'. "
                        f"Violates infrastructure zero-ingress perimeter policy (all direct external threads are prohibited)."
                    ),
                    rule_violated="POLICY-NET-ZERO-EXTERNAL-INGRESS: No Inbound Threads / Connections From Outside Infrastructure Allowed",
                    remediation_taken="CONNECTION_TERMINATED_AND_DROPPED: Severed TCP thread at Cilium eBPF edge and injected default-deny perimeter NetworkPolicy",
                    technical_trace={
                        "source_external_ip": packet.source_ip,
                        "target_pod": pod_state.pod_name,
                        "target_agent": pod_state.agent_name,
                        "target_port": packet.destination_port,
                        "protocol": packet.protocol,
                        "allowed_ingress_manifest": allowed_sources,
                        "payload_summary": packet.payload_summary,
                        "payload_snippet": packet.payload_content[:150],
                        "headers": packet.headers
                    }
                )
                self._quarantine_pod(pod_state, f"Unauthorized external inbound thread from {packet.source_ip}")
                
                mitigation = AutoCorrectMitigation(
                    incident_id=incident.incident_id,
                    target_pod=pod_state.pod_name,
                    target_agent=pod_state.agent_name,
                    target_namespace=pod_state.namespace,
                    title=f"Block External Ingress & Seal Pod Ingress Perimeter",
                    recommended_action=f"Apply strict CiliumNetworkPolicy restricting ingress on '{pod_state.pod_name}' to internal cluster CIDRs only, dropping all external threads.",
                    action_type="NETWORK_POLICY_ISOLATION",
                    confidence_score=99,
                    requires_human_approval=True,
                    status=MitigationStatus.AWAITING_APPROVAL,
                    action_diff=f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-external-ingress-{pod_state.agent_name}
  namespace: {pod_state.namespace}
spec:
  endpointSelector:
    matchLabels:
      app: {pod_state.agent_name}
  ingress:
  - fromCIDR:
    - 10.244.0.0/16
    # REJECT ALL EXTERNAL INTERNET / OUTSIDE INFRA (0.0.0.0/0)"""
                )
                incident.mitigation = mitigation
                self.mitigations.insert(0, mitigation)
                self._record_incident(incident)
                return incident

            # Check prompt injection patterns on internal ingress
            for pattern in self.injection_patterns:
                if pattern.search(packet.payload_content):
                    incident = SecurityIncident(
                        severity=Severity.HIGH,
                        category=IncidentCategory.INGRESS_PROMPT_INJECTION,
                        agent_id=pod_state.agent_id,
                        agent_name=pod_state.agent_name,
                        pod_name=pod_state.pod_name,
                        namespace=pod_state.namespace,
                        title=f"Ingress Prompt Injection Attempt on {pod_state.agent_name}",
                        description="Malicious user input attempted to override agent instructions or jailbreak sandboxing.",
                        rule_violated="POLICY-INGRESS-004: Anti-Prompt-Injection Gateway Shield",
                        remediation_taken="PACKET_DROPPED: Filtered malicious payload at Ingress controller before reaching agent model",
                        technical_trace={
                            "matched_pattern": pattern.pattern,
                            "source_ip": packet.source_ip,
                            "payload_snippet": packet.payload_content[:150],
                            "headers": packet.headers
                        }
                    )
                    mitigation = AutoCorrectMitigation(
                        incident_id=incident.incident_id,
                        target_pod=pod_state.pod_name,
                        target_agent=pod_state.agent_name,
                        target_namespace=pod_state.namespace,
                        title="Update Ingress WAF & Ban Attacker IP",
                        recommended_action="Inject dynamic Envoy WAF rule to block source IP and sanitize prompt headers.",
                        action_type="PAYLOAD_DROP",
                        confidence_score=98,
                        requires_human_approval=True,
                        status=MitigationStatus.AWAITING_APPROVAL,
                        action_diff="""+ IngressFilter.rules.append(BlockPattern: "{pattern}")
+ CiliumNetworkPolicy.ingress.deny(ip: "{ip}")""".format(pattern=pattern.pattern, ip=packet.source_ip)
                    )
                    incident.mitigation = mitigation
                    self.mitigations.insert(0, mitigation)
                    self._record_incident(incident)
                    return incident

        # 3. Strict Internet Egress Detection
        if packet.direction == "EGRESS":
            dest_host = packet.destination.split(":")[0]
            if self._is_public_internet_destination(dest_host):
                incident = SecurityIncident(
                    severity=Severity.CRITICAL,
                    category=IncidentCategory.EGRESS_EXFILTRATION,
                    agent_id=pod_state.agent_id,
                    agent_name=pod_state.agent_name,
                    pod_name=pod_state.pod_name,
                    namespace=pod_state.namespace,
                    title=f"UNAUTHORIZED INTERNET ACCESS: {pod_state.agent_name} -> {packet.destination}:{packet.destination_port}",
                    description=f"Agent breached sandbox by initiating an unapproved direct outbound connection to the Public Internet ({packet.destination}:{packet.destination_port}).",
                    rule_violated="POLICY-NET-ZERO-EGRESS: Agents Prohibited From Direct Public Internet Egress",
                    remediation_taken="AUTO_QUARANTINED: Injected K8s Cilium NetworkPolicy default-deny Internet egress, severed TCP socket",
                    technical_trace={
                        "destination_ip_host": packet.destination,
                        "destination_port": packet.destination_port,
                        "protocol": packet.protocol,
                        "source_pod": pod_state.pod_name,
                        "source_namespace": pod_state.namespace,
                        "allowed_manifest_destinations": pod_state.manifest.allowed_egress_destinations,
                        "packet_id": packet.packet_id,
                        "payload_summary": packet.payload_summary,
                        "exfiltrated_snippet": packet.payload_content[:200]
                    }
                )
                self._quarantine_pod(pod_state, f"Unauthorized internet egress attempt to {packet.destination}")
                
                mitigation = AutoCorrectMitigation(
                    incident_id=incident.incident_id,
                    target_pod=pod_state.pod_name,
                    target_agent=pod_state.agent_name,
                    target_namespace=pod_state.namespace,
                    title=f"Auto-Remediate Pod Egress & Reinstate Restricted Sandbox",
                    recommended_action="Deploy strict Egress CiliumNetworkPolicy, purge rogue subprocesses, and restore Pod Trust Score.",
                    action_type="NETWORK_POLICY_ISOLATION",
                    confidence_score=96,
                    requires_human_approval=True,
                    status=MitigationStatus.AWAITING_APPROVAL,
                    action_diff="""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: isolate-{agent}
  namespace: {ns}
spec:
  endpointSelector:
    matchLabels:
      app: {agent}
  egress:
  - toEntities:
    - cluster
    # PUBLIC INTERNET (0.0.0.0/0) EXCLUDED""".format(agent=pod_state.agent_name, ns=pod_state.namespace)
                )
                incident.mitigation = mitigation
                self.mitigations.insert(0, mitigation)
                self._record_incident(incident)
                return incident

        # 4. Unauthorized Agent-to-Agent Inter-Pod Permissions
        if packet.direction == "POD_TO_POD":
            dest_host = packet.destination.split(":")[0]
            dest_parts = dest_host.split(".")
            dest_service_or_pod = dest_parts[0]
            dest_ns = dest_parts[1] if len(dest_parts) > 1 else pod_state.namespace

            allowed_scopes = pod_state.manifest.allowed_data_scopes
            allowed_egress = pod_state.manifest.allowed_egress_destinations
            
            permitted = (
                (dest_ns == pod_state.namespace) or 
                (dest_ns in allowed_scopes) or
                any(dest_service_or_pod in allowed for allowed in allowed_egress)
            )

            if not permitted:
                incident = SecurityIncident(
                    severity=Severity.HIGH,
                    category=IncidentCategory.LATERAL_MOVEMENT_SCAN,
                    agent_id=pod_state.agent_id,
                    agent_name=pod_state.agent_name,
                    pod_name=pod_state.pod_name,
                    namespace=pod_state.namespace,
                    title=f"UNAUTHORIZED AGENT-TO-AGENT ACCESS: {pod_state.agent_name} attempted to contact {packet.destination}",
                    description=f"Agent reached out to another agent/service in namespace '{dest_ns}' without required mutual TLS authorization and inter-agent permissions.",
                    rule_violated="POLICY-A2A-PERMISSIONS-009: Strict Inter-Agent Scope & mTLS Authorization Required",
                    remediation_taken="PACKET_DROPPED_AND_ALERTED: Applied Istio/Cilium service-to-service authorization denial & logged for forensic review",
                    technical_trace={
                        "source_agent": pod_state.agent_name,
                        "source_pod": pod_state.pod_name,
                        "source_namespace": pod_state.namespace,
                        "target_destination": packet.destination,
                        "target_namespace": dest_ns,
                        "allowed_agent_scopes": allowed_scopes,
                        "payload_summary": packet.payload_summary,
                        "attempted_command": packet.payload_content[:180]
                    }
                )
                mitigation = AutoCorrectMitigation(
                    incident_id=incident.incident_id,
                    target_pod=pod_state.pod_name,
                    target_agent=pod_state.agent_name,
                    target_namespace=pod_state.namespace,
                    title="Enforce Istio AuthorizationPolicy Cross-Namespace Deny",
                    recommended_action=f"Auto-generate Istio AuthorizationPolicy denying traffic from '{pod_state.namespace}' to '{dest_ns}'.",
                    action_type="NETWORK_POLICY_ISOLATION",
                    confidence_score=94,
                    requires_human_approval=True,
                    status=MitigationStatus.AWAITING_APPROVAL,
                    action_diff="""apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: block-{src}-to-{dest}
  namespace: {dest}
spec:
  action: DENY
  rules:
  - from:
    - source:
        namespaces: ["{src}"]""".format(src=pod_state.namespace, dest=dest_ns)
                )
                incident.mitigation = mitigation
                self.mitigations.insert(0, mitigation)
                self._record_incident(incident)
                return incident

        return None

    def inspect_audit_event(self, event: AuditSyscallEvent, pod_state: PodState) -> Optional[SecurityIncident]:
        self.rules_evaluated_count += 3

        # 1. RBAC & K8s API privilege escalation
        if event.action_type == "k8s_api":
            allowed_verbs = pod_state.manifest.allowed_k8s_api_verbs
            if event.verb and event.verb not in allowed_verbs:
                incident = SecurityIncident(
                    severity=Severity.CRITICAL,
                    category=IncidentCategory.RBAC_PRIVILEGE_ESCALATION,
                    agent_id=pod_state.agent_id,
                    agent_name=pod_state.agent_name,
                    pod_name=pod_state.pod_name,
                    namespace=pod_state.namespace,
                    title=f"Privilege Escalation / RBAC Bypass attempted by {pod_state.agent_name}",
                    description=f"Agent issued unapproved verb '{event.verb}' on resource '{event.target_resource}' via mounted ServiceAccount.",
                    rule_violated="POLICY-RBAC-007: Least-Privilege Pod ServiceAccount Bounds",
                    remediation_taken="TOKEN_REVOKED: Pod ServiceAccount Token invalidated in API server; Pod cordoned",
                    technical_trace={
                        "attempted_verb": event.verb,
                        "allowed_verbs": allowed_verbs,
                        "target_resource": event.target_resource,
                        "event_id": event.event_id
                    }
                )
                self._quarantine_pod(pod_state, f"RBAC violation: verb '{event.verb}' on '{event.target_resource}'")
                mitigation = AutoCorrectMitigation(
                    incident_id=incident.incident_id,
                    target_pod=pod_state.pod_name,
                    target_agent=pod_state.agent_name,
                    target_namespace=pod_state.namespace,
                    title="Rotate Pod ServiceAccount & Strip ClusterRoleBinding",
                    recommended_action="Revoke compromised token, rotate service account secrets, and bind read-only Role.",
                    action_type="RBAC_TOKEN_REVOCATION",
                    confidence_score=99,
                    requires_human_approval=True,
                    status=MitigationStatus.AWAITING_APPROVAL,
                action_diff=f"""kubectl delete secret {pod_state.agent_name}-token -n {pod_state.namespace}
kubectl apply -f role-readonly.yaml
kubectl patch serviceaccount {pod_state.agent_name} -p '{{"automountServiceAccountToken": false}}'"""
                )
                incident.mitigation = mitigation
                self.mitigations.insert(0, mitigation)
                self._record_incident(incident)
                return incident

        # 2. Filesystem sandbox & path traversal escape
        if event.action_type == "file_access":
            target = event.target_resource
            for forbidden in self.forbidden_paths:
                if target.startswith(forbidden):
                    incident = SecurityIncident(
                        severity=Severity.CRITICAL,
                        category=IncidentCategory.UNAUTHORIZED_FILESYSTEM_ACCESS,
                        agent_id=pod_state.agent_id,
                        agent_name=pod_state.agent_name,
                        pod_name=pod_state.pod_name,
                        namespace=pod_state.namespace,
                        title=f"Filesystem Sandbox Traversal Breached in {pod_state.pod_name}",
                        description=f"Agent attempted to read out-of-sandbox protected path '{target}'.",
                        rule_violated="POLICY-SANDBOX-001: Strict Container Filesystem Sandboxing",
                        remediation_taken="CONTAINER_FROZEN: cgroup v2 freezer triggered, memory core dumped for forensics",
                        technical_trace={
                            "attempted_path": target,
                            "allowed_paths": pod_state.manifest.allowed_filesystem_paths,
                            "event_id": event.event_id
                        }
                    )
                    self._quarantine_pod(pod_state, f"Filesystem traversal attempt on '{target}'")
                    mitigation = AutoCorrectMitigation(
                        incident_id=incident.incident_id,
                        target_pod=pod_state.pod_name,
                        target_agent=pod_state.agent_name,
                        target_namespace=pod_state.namespace,
                        title="Enforce AppArmor Profile & ReadOnlyRootFilesystem",
                        recommended_action="Unfreeze container, apply strict AppArmor profile to forbid host mount reads, and mount tmpfs scratchpad.",
                        action_type="CGROUP_FREEZE",
                        confidence_score=97,
                        requires_human_approval=True,
                        status=MitigationStatus.AWAITING_APPROVAL,
                        action_diff="""securityContext:
  readOnlyRootFilesystem: true
  appArmorProfile:
    type: Localhost
    localhostProfile: k8s-agent-strict-sandbox"""
                    )
                    incident.mitigation = mitigation
                    self.mitigations.insert(0, mitigation)
                    self._record_incident(incident)
                    return incident

        return None

    def execute_human_approval(self, mitigation_id: str, operator_name: str, action: str, operator_notes: Optional[str], cluster_pods: Dict[str, PodState]) -> Optional[AutoCorrectMitigation]:
        """Human-in-the-Loop decision handler."""
        mitigation = next((m for m in self.mitigations if m.mitigation_id == mitigation_id), None)
        if not mitigation:
            return None

        mitigation.reviewed_at = time.time()
        mitigation.reviewed_by = operator_name
        mitigation.operator_notes = operator_notes

        if action == "APPROVE":
            mitigation.status = MitigationStatus.APPROVED
            self.remediations_executed_count += 1
            # Apply remediation effect on the target pod
            pod = cluster_pods.get(mitigation.target_pod)
            if pod:
                pod.quarantined = False
                pod.throttled = False
                pod.tokens_consumed_current_window = 0
                pod.status = PodStatus.RUNNING
                pod.security_score = min(100, pod.security_score + 40)
                pod.quarantine_reason = None
        elif action == "REJECT":
            mitigation.status = MitigationStatus.REJECTED
        elif action == "ROLLBACK":
            mitigation.status = MitigationStatus.ROLLED_BACK

        # Update matching incident record
        for inc in self.incidents:
            if inc.mitigation and inc.mitigation.mitigation_id == mitigation_id:
                inc.mitigation = mitigation
                if action == "APPROVE":
                    inc.status = "RESOLVED_BY_OPERATOR"
                    inc.remediation_taken = f"AUTO_CORRECT_EXECUTED: Operator ({operator_name}) approved {mitigation.title}"

        return mitigation

    def _quarantine_pod(self, pod_state: PodState, reason: str):
        pod_state.status = PodStatus.ISOLATED
        pod_state.quarantined = True
        pod_state.quarantine_reason = reason
        pod_state.security_score = max(0, pod_state.security_score - 50)
        self.remediations_executed_count += 1

    def _record_incident(self, incident: SecurityIncident):
        self.incidents.insert(0, incident)
        if len(self.incidents) > 200:
            self.incidents.pop()

    def get_stats(self) -> Dict[str, Any]:
        critical_count = sum(1 for i in self.incidents if i.severity == Severity.CRITICAL)
        high_count = sum(1 for i in self.incidents if i.severity == Severity.HIGH)
        medium_count = sum(1 for i in self.incidents if i.severity == Severity.MEDIUM)
        pending_mitigations = sum(1 for m in self.mitigations if m.status == MitigationStatus.AWAITING_APPROVAL)
        approved_mitigations = sum(1 for m in self.mitigations if m.status == MitigationStatus.APPROVED)
        
        return {
            "total_incidents": len(self.incidents),
            "critical_incidents": critical_count,
            "high_incidents": high_count,
            "medium_incidents": medium_count,
            "rules_evaluated": self.rules_evaluated_count,
            "packets_inspected": self.packets_inspected_count,
            "remediations_executed": self.remediations_executed_count,
            "pending_mitigations": pending_mitigations,
            "approved_mitigations": approved_mitigations
        }
