from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time
import uuid

class PodStatus(str, Enum):
    RUNNING = "Running"
    ISOLATED = "Isolated (Quarantined)"
    ALERTING = "Alerting"
    SUSPENDED = "Suspended"
    THROTTLED = "Throttled (Rate Limited)"

class TrafficDirection(str, Enum):
    INGRESS = "INGRESS"
    EGRESS = "EGRESS"
    INTERNAL_POD_TO_POD = "POD_TO_POD"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentCategory(str, Enum):
    EGRESS_EXFILTRATION = "EGRESS_EXFILTRATION"
    INGRESS_PROMPT_INJECTION = "INGRESS_PROMPT_INJECTION"
    SANDBOX_ESCAPE_ATTEMPT = "SANDBOX_ESCAPE_ATTEMPT"
    RBAC_PRIVILEGE_ESCALATION = "RBAC_PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT_SCAN = "LATERAL_MOVEMENT_SCAN"
    ROGUE_BEHAVIOR_DRIFT = "ROGUE_BEHAVIOR_DRIFT"
    UNAUTHORIZED_FILESYSTEM_ACCESS = "UNAUTHORIZED_FILESYSTEM_ACCESS"
    ANOMALOUS_TOKEN_CONSUMPTION = "ANOMALOUS_TOKEN_CONSUMPTION"
    EXTERNAL_UNTRUSTED_INGRESS_THREAT = "EXTERNAL_UNTRUSTED_INGRESS_THREAT"

class MitigationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    AUTO_EXECUTED = "AUTO_EXECUTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"

class AutoCorrectMitigation(BaseModel):
    mitigation_id: str = Field(default_factory=lambda: f"MIT-{str(uuid.uuid4())[:8].upper()}")
    incident_id: str
    target_pod: str
    target_agent: str
    target_namespace: str
    title: str
    recommended_action: str
    action_type: str  # NETWORK_POLICY_ISOLATION, RBAC_TOKEN_REVOCATION, CGROUP_FREEZE, PAYLOAD_DROP, TOKEN_RATE_LIMIT, DNS_SINKHOLE
    confidence_score: int = 95
    requires_human_approval: bool = True
    status: MitigationStatus = MitigationStatus.AWAITING_APPROVAL
    proposed_at: float = Field(default_factory=time.time)
    reviewed_at: Optional[float] = None
    reviewed_by: Optional[str] = None
    operator_notes: Optional[str] = None
    action_diff: Optional[str] = None

class AgentManifest(BaseModel):
    agent_id: str
    name: str
    role: str
    namespace: str
    pod_name: str
    pod_ip: str
    node_name: str
    allowed_ingress_sources: List[str]
    allowed_egress_destinations: List[str]
    allowed_k8s_api_verbs: List[str]
    allowed_data_scopes: List[str]
    allowed_filesystem_paths: List[str]
    max_tokens_per_minute: int = 15000

class PodState(BaseModel):
    pod_name: str
    agent_id: str
    agent_name: str
    namespace: str
    ip: str
    node: str
    status: PodStatus = PodStatus.RUNNING
    active_connections: int = 0
    security_score: int = 100
    quarantined: bool = False
    last_activity: float = Field(default_factory=time.time)
    quarantine_reason: Optional[str] = None
    tokens_consumed_current_window: int = 0
    token_window_start: float = Field(default_factory=time.time)
    throttled: bool = False
    manifest: AgentManifest

class NetworkTrafficPacket(BaseModel):
    packet_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = Field(default_factory=time.time)
    direction: TrafficDirection
    source_pod: str
    source_agent: str
    source_namespace: str
    source_ip: str
    destination: str
    destination_port: int
    protocol: str = "TCP"
    payload_summary: str
    payload_content: str
    tokens_used: int = 0
    headers: Dict[str, str] = Field(default_factory=dict)

class AuditSyscallEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = Field(default_factory=time.time)
    pod_name: str
    agent_name: str
    namespace: str
    action_type: str  # k8s_api, exec_command, file_access, secret_read, token_quota
    target_resource: str
    command_executed: Optional[str] = None
    verb: Optional[str] = None

class SecurityIncident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"SEC-{str(uuid.uuid4())[:8].upper()}")
    timestamp: float = Field(default_factory=time.time)
    severity: Severity
    category: IncidentCategory
    agent_id: str
    agent_name: str
    pod_name: str
    namespace: str
    title: str
    description: str
    technical_trace: Dict[str, Any]
    rule_violated: str
    remediation_taken: str
    status: str = "ACTIVE"
    mitigation: Optional[AutoCorrectMitigation] = None
