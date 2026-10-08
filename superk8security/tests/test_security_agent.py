
from app.cluster_simulator import KubernetesClusterSimulator
from app.security_agent import SuperK8SecurityAgent
from app.models import PodStatus, Severity, IncidentCategory

def test_initialization():
    sim = KubernetesClusterSimulator()
    assert len(sim.pods) == 10
    agent = SuperK8SecurityAgent()
    assert agent.packets_inspected_count == 0
    assert len(agent.incidents) == 0

def test_exfiltration_detection_and_quarantine():
    sim = KubernetesClusterSimulator()
    agent = SuperK8SecurityAgent()
    
    packet = sim.trigger_attack_exfiltration()
    pod = sim.pods[packet.source_pod]
    
    incident = agent.inspect_network_traffic(packet, pod)
    assert incident is not None
    assert incident.category == IncidentCategory.EGRESS_EXFILTRATION
    assert incident.severity == Severity.CRITICAL
    assert pod.status == PodStatus.ISOLATED
    assert pod.quarantined is True

def test_prompt_injection_ingress_detection():
    sim = KubernetesClusterSimulator()
    agent = SuperK8SecurityAgent()
    
    packet = sim.trigger_attack_prompt_injection()
    pod = sim.pods[packet.source_pod]
    
    incident = agent.inspect_network_traffic(packet, pod)
    assert incident is not None
    assert incident.category == IncidentCategory.INGRESS_PROMPT_INJECTION
    assert "Ignore all previous instructions" in incident.technical_trace["matched_pattern"] or incident.severity == Severity.HIGH

def test_rbac_privilege_escalation():
    sim = KubernetesClusterSimulator()
    agent = SuperK8SecurityAgent()
    
    event = sim.trigger_attack_rbac_escalation()
    pod = sim.pods[event.pod_name]
    
    incident = agent.inspect_audit_event(event, pod)
    assert incident is not None
    assert incident.category == IncidentCategory.RBAC_PRIVILEGE_ESCALATION
    assert pod.quarantined is True

def test_filesystem_sandbox_escape():
    sim = KubernetesClusterSimulator()
    agent = SuperK8SecurityAgent()
    
    event = sim.trigger_attack_filesystem_escape()
    pod = sim.pods[event.pod_name]
    
    incident = agent.inspect_audit_event(event, pod)
    assert incident is not None
    assert incident.category == IncidentCategory.UNAUTHORIZED_FILESYSTEM_ACCESS
    assert pod.quarantined is True

if __name__ == "__main__":
    test_initialization()
    test_exfiltration_detection_and_quarantine()
    test_prompt_injection_ingress_detection()
    test_rbac_privilege_escalation()
    test_filesystem_sandbox_escape()
    print("ALL TESTS PASSED SUCCESSFULLY!")
