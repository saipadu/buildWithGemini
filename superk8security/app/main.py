import asyncio
import json
import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.models import PodState, SecurityIncident, AutoCorrectMitigation
from app.cluster_simulator import KubernetesClusterSimulator
from app.security_agent import SuperK8SecurityAgent
from app.attack_scenarios import DynamicBreachGenerator

app = FastAPI(title="SuperK8Security Platform", version="1.0.0")

# Mount static directory for the SOC alert dashboard
app.mount("/static", StaticFiles(directory="/config/Desktop/Session1/superk8security/static"), name="static")

simulator = KubernetesClusterSimulator()
security_agent = SuperK8SecurityAgent()
breach_generator = DynamicBreachGenerator(simulator)

# Active WebSocket subscribers
active_websockets: List[WebSocket] = []

# Automated Periodic Breach Campaign State (Every 1 minute)
periodic_breach_enabled = True
periodic_breach_interval_seconds = 60
last_periodic_breach_timestamp = 0.0
periodic_breach_history = []

async def broadcast_state():
    if not active_websockets:
        return
    
    state_payload = {
        "type": "CLUSTER_UPDATE",
        "pods": [pod.dict() for pod in simulator.pods.values()],
        "incidents": [inc.dict() for inc in security_agent.incidents[:50]],
        "mitigations": [m.dict() for m in security_agent.mitigations[:50]],
        "stats": security_agent.get_stats(),
        "periodic_breach": {
            "enabled": periodic_breach_enabled,
            "interval_seconds": periodic_breach_interval_seconds,
            "last_breach_time": last_periodic_breach_timestamp,
            "next_breach_in_seconds": max(0, int(periodic_breach_interval_seconds - (time.time() - last_periodic_breach_timestamp))) if last_periodic_breach_timestamp > 0 else 0
        }
    }
    dead_connections = []
    for ws in active_websockets:
        try:
            await ws.send_text(json.dumps(state_payload))
        except Exception:
            dead_connections.append(ws)
    for ws in dead_connections:
        if ws in active_websockets:
            active_websockets.remove(ws)

simulation_running = True

async def background_telemetry_and_breach_loop():
    global last_periodic_breach_timestamp
    while simulation_running:
        try:
            now = time.time()

            # 1. Check if 1 minute has elapsed for the scheduled breach
            if periodic_breach_enabled and (now - last_periodic_breach_timestamp >= periodic_breach_interval_seconds):
                last_periodic_breach_timestamp = now
                event_type, event_obj, target_pod, label = breach_generator.next_breach()
                
                incident = None
                if event_type == "PACKET":
                    incident = security_agent.inspect_network_traffic(event_obj, target_pod)
                elif event_type == "SYSCALL":
                    incident = security_agent.inspect_audit_event(event_obj, target_pod)
                
                if incident:
                    periodic_breach_history.append({
                        "time": now,
                        "agent": target_pod.agent_name,
                        "use_case": label,
                        "incident_id": incident.incident_id,
                        "severity": incident.severity
                    })
                    print(f"[PERIODIC BREACH ENGINE] Triggered {label} on {target_pod.agent_name} -> {incident.incident_id} ({incident.severity})")
                await broadcast_state()

            # 2. Benign ambient cluster telemetry
            packet = simulator.generate_benign_traffic()
            if packet:
                pod = simulator.pods.get(packet.source_pod)
                if pod:
                    incident = security_agent.inspect_network_traffic(packet, pod)
                    if incident:
                        await broadcast_state()

            await asyncio.sleep(2.0)
            await broadcast_state()
        except Exception as e:
            print(f"Error in telemetry loop: {e}")
            await asyncio.sleep(2.0)

@app.on_event("startup")
async def startup_event():
    # Trigger first breach immediately on startup so dashboard has live data
    global last_periodic_breach_timestamp
    last_periodic_breach_timestamp = time.time()
    event_type, event_obj, target_pod, label = breach_generator.next_breach()
    if event_type == "PACKET":
        security_agent.inspect_network_traffic(event_obj, target_pod)
    elif event_type == "SYSCALL":
        security_agent.inspect_audit_event(event_obj, target_pod)
    
    asyncio.create_task(background_telemetry_and_breach_loop())

@app.get("/")
@app.get("/devmode")
@app.get("/devmode/")
async def root():
    return FileResponse("/config/Desktop/Session1/superk8security/static/index.html")

app.mount("/devmode/static", StaticFiles(directory="/config/Desktop/Session1/superk8security/static"), name="devmode_static")

@app.get("/api/pods")
async def get_pods():
    return [pod.dict() for pod in simulator.pods.values()]

@app.get("/api/incidents")
async def get_incidents():
    return [inc.dict() for inc in security_agent.incidents]

@app.get("/api/mitigations")
async def get_mitigations():
    return [m.dict() for m in security_agent.mitigations]

@app.get("/api/stats")
async def get_stats():
    return security_agent.get_stats()

@app.get("/api/periodic-breach/status")
async def get_periodic_breach_status():
    return {
        "enabled": periodic_breach_enabled,
        "interval_seconds": periodic_breach_interval_seconds,
        "last_breach_time": last_periodic_breach_timestamp,
        "next_breach_in_seconds": max(0, int(periodic_breach_interval_seconds - (time.time() - last_periodic_breach_timestamp))),
        "history": periodic_breach_history[-10:]
    }

@app.post("/api/periodic-breach/toggle")
async def toggle_periodic_breach(enable: Optional[bool] = None):
    global periodic_breach_enabled
    if enable is not None:
        periodic_breach_enabled = enable
    else:
        periodic_breach_enabled = not periodic_breach_enabled
    await broadcast_state()
    return {"status": "SUCCESS", "enabled": periodic_breach_enabled}

@app.post("/api/periodic-breach/trigger-now")
async def trigger_periodic_breach_now():
    global last_periodic_breach_timestamp
    last_periodic_breach_timestamp = time.time()
    event_type, event_obj, target_pod, label = breach_generator.next_breach()
    incident = None
    if event_type == "PACKET":
        incident = security_agent.inspect_network_traffic(event_obj, target_pod)
    elif event_type == "SYSCALL":
        incident = security_agent.inspect_audit_event(event_obj, target_pod)
    
    if incident:
        periodic_breach_history.append({
            "time": last_periodic_breach_timestamp,
            "agent": target_pod.agent_name,
            "use_case": label,
            "incident_id": incident.incident_id,
            "severity": incident.severity
        })
    await broadcast_state()
    return {
        "status": "SUCCESS",
        "use_case": label,
        "target_agent": target_pod.agent_name,
        "incident": incident.dict() if incident else None
    }

class HumanApprovalRequest(BaseModel):
    operator_name: str = "Lead Security Architect"
    action: str  # "APPROVE", "REJECT", "ROLLBACK"
    operator_notes: Optional[str] = "Auto-correct verified and approved by human operator."

@app.post("/api/mitigations/{mitigation_id}/action")
async def handle_mitigation_action(mitigation_id: str, request: HumanApprovalRequest):
    mitigation = security_agent.execute_human_approval(
        mitigation_id=mitigation_id,
        operator_name=request.operator_name,
        action=request.action,
        operator_notes=request.operator_notes,
        cluster_pods=simulator.pods
    )
    if not mitigation:
        raise HTTPException(status_code=404, detail="Mitigation proposal not found")
    
    await broadcast_state()
    return {
        "status": "SUCCESS",
        "action_taken": request.action,
        "mitigation": mitigation.dict()
    }

@app.post("/api/simulate/attack/{scenario}")
async def trigger_attack(scenario: str):
    incident = None
    if scenario == "internet_outreach":
        packet = simulator.trigger_attack_internet_outreach()
        pod = simulator.pods[packet.source_pod]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "unauthorized_agent_to_agent":
        packet = simulator.trigger_attack_unauthorized_agent_to_agent()
        pod = simulator.pods[packet.source_pod]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "exfiltration":
        packet = simulator.trigger_attack_exfiltration()
        pod = simulator.pods[packet.source_pod]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "prompt_injection":
        packet = simulator.trigger_attack_prompt_injection()
        pod = simulator.pods[packet.source_pod]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "rbac_escalation":
        event = simulator.trigger_attack_rbac_escalation()
        pod = simulator.pods[event.pod_name]
        incident = security_agent.inspect_audit_event(event, pod)
    elif scenario == "filesystem_escape":
        event = simulator.trigger_attack_filesystem_escape()
        pod = simulator.pods[event.pod_name]
        incident = security_agent.inspect_audit_event(event, pod)
    elif scenario == "anomalous_tokens":
        packet = simulator.trigger_attack_anomalous_tokens()
        pod = simulator.pods[packet.source_pod]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "external_ingress_thread":
        packet = simulator.trigger_attack_external_ingress_thread()
        pod = simulator.pods[packet.destination.split(":")[0]] if packet.destination.split(":")[0] in simulator.pods else [p for p in simulator.pods.values() if p.agent_name == "agent-auth-sync"][0]
        incident = security_agent.inspect_network_traffic(packet, pod)
    elif scenario == "reset":
        simulator.reset_pod_quarantines()
        security_agent.incidents.clear()
        security_agent.mitigations.clear()
        await broadcast_state()
        return {"status": "SUCCESS", "message": "Cluster quarantined pods, incidents, and mitigations reset to baseline."}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack scenario '{scenario}'")

    await broadcast_state()
    return {
        "status": "INCIDENT_DETECTED" if incident else "NO_BREACH",
        "incident": incident.dict() if incident else None
    }

@app.websocket("/ws")
@app.websocket("/devmode/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    state_payload = {
        "type": "INITIAL_STATE",
        "pods": [pod.dict() for pod in simulator.pods.values()],
        "incidents": [inc.dict() for inc in security_agent.incidents[:50]],
        "mitigations": [m.dict() for m in security_agent.mitigations[:50]],
        "stats": security_agent.get_stats(),
        "periodic_breach": {
            "enabled": periodic_breach_enabled,
            "interval_seconds": periodic_breach_interval_seconds,
            "last_breach_time": last_periodic_breach_timestamp,
            "next_breach_in_seconds": max(0, int(periodic_breach_interval_seconds - (time.time() - last_periodic_breach_timestamp))) if last_periodic_breach_timestamp > 0 else 0
        }
    }
    await websocket.send_text(json.dumps(state_payload))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

# Mount for Architecture Slides Presentation
@app.get("/slides")
@app.get("/slides/")
@app.get("/devmode/slides")
@app.get("/devmode/slides/")
async def slides_root():
    return FileResponse("/config/Desktop/Session1/superk8security/slides/index.html")

app.mount("/slides/assets", StaticFiles(directory="/config/Desktop/Session1/superk8security/slides"), name="slides_assets")

# Evidence Logs Download Route
@app.get("/api/evidence/audit.json")
async def get_evidence_json():
    return FileResponse("/config/Desktop/Session1/superk8security/evidence/security_incidents_audit.json", filename="superk8security_audit.json", media_type="application/json")

@app.get("/api/evidence/audit.log")
async def get_evidence_log():
    return FileResponse("/config/Desktop/Session1/superk8security/evidence/security_audit.log", filename="superk8security_audit.log", media_type="text/plain")

@app.get("/api/evidence/report.md")
async def get_evidence_report():
    return FileResponse("/config/Desktop/Session1/superk8security/evidence/EVIDENCE_REPORT.md", filename="superk8security_report.md", media_type="text/markdown")
