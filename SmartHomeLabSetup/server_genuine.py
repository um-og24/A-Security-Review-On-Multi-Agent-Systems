# server_genuine.py - Single Smart Home Agent Server (one per container)
"""
Each container runs one agent type, determined by the AGENT_TYPE env var.
Serves its A2A v0.3.0 Agent Card at:
  /.well-known/agent-card.json

Responds to JSON-RPC 2.0 message/send at:
  /a2a
"""

import json, os, sys, uuid
from flask import Flask, jsonify, request
from datetime import datetime, timezone
from log_client import log_event
from config_manager import ConfigManager
from a2a_models import build_agent_card, SMART_HOME_AGENTS, DEVICE_TIERS

app = Flask("genuine-agent")

AGENT_TYPE = os.environ.get("AGENT_TYPE", "thermostat")
HOSTNAME = os.environ.get("GENUINE_HOSTNAME", DEVICE_TIERS.get(AGENT_TYPE, {}).get("hostname", "smarthome.example.com"))
PORT = int(os.environ["GENUINE_PORT"])
CERT_DIR = "/certs"
PRIVATE_KEY_PATH = os.path.join(CERT_DIR, "genuine.key")
CERT_PATH = os.path.join(CERT_DIR, "genuine.crt")
PUBKEY_PATH = os.path.join(CERT_DIR, "genuine.pub.pem")
VALID_TOKEN = os.environ["VALID_PUSH_TOKEN"]

config_manager = ConfigManager(os.environ["CONFIG_PATH"])

# ---------------------------------------------------------------------------
# Scenario L — Scope Escalation: tasks that require elevated privilege.
# With scope_enforcement=False (default / vulnerable) the server accepts any
# of these from any caller holding a valid bearer token.
# With scope_enforcement=True (defended) they are rejected with 403.
# ---------------------------------------------------------------------------
RESTRICTED_TASKS = {
    "unlock_all_doors",
    "provision_master_token",
    "add_access_code",
    "disable_alarm",
}

# Load signing key
PRIVATE_KEY = None
if os.path.exists(PRIVATE_KEY_PATH):
    with open(PRIVATE_KEY_PATH, "rb") as f:
        PRIVATE_KEY = f.read()


# ---------------------------------------------------------------------------
# Simulated agent state (for realistic responses)
# ---------------------------------------------------------------------------

AGENT_STATES = {
    "thermostat": {
        "current_temp_c": 21.5,
        "target_temp_c": 22.0,
        "mode": "heating",
        "zones": {"living_room": 21.5, "bedroom": 20.0, "kitchen": 22.0}
    },
    "security-camera": {
        "cameras": {
            "front-door": {"status": "online", "recording": True},
            "garden": {"status": "online", "recording": False},
            "garage": {"status": "offline", "recording": False}
        }
    },
    "door-lock": {
        "locks": {
            "front-door": {"status": "locked", "battery": 85},
            "back-door": {"status": "locked", "battery": 92},
            "garage": {"status": "unlocked", "battery": 45}
        }
    },
    "lighting": {
        "rooms": {
            "living_room": {"brightness": 80, "scene": "default"},
            "bedroom": {"brightness": 0, "scene": "off"},
            "kitchen": {"brightness": 100, "scene": "bright"}
        }
    }
}


def _lab_context():
    lab = config_manager.get_section("lab")
    return lab.get("active_experiment", "manual"), lab.get("active_experiment", "manual")

def _validate_auth(req):
    """Validate bearer token authentication."""
    auth = req.headers.get("Authorization", "")
    token = req.headers.get("X-A2A-Notification-Token", "")
    bearer = None
    if auth.lower().startswith("bearer "):
        bearer = auth.split(" ", 1)[1].strip()
    actual_token = bearer or token
    if not actual_token:
        return False, "no_token"
    if actual_token != VALID_TOKEN:
        return False, "invalid_token"
    return True, "ok"


def _make_genuine_response(task_text, request_id):
    """Generate a realistic A2A JSON-RPC response based on agent type and task."""
    state = AGENT_STATES.get(AGENT_TYPE, {})
    response_text = f"[{AGENT_TYPE}] Task acknowledged."
    response_data = {"status": "completed", "agent": AGENT_TYPE}

    task_lower = task_text.lower() if task_text else ""

    if AGENT_TYPE == "thermostat":
        if "temperature" in task_lower or "set" in task_lower:
            response_text = (f"Living room temperature set to {state.get('target_temp_c', 22)}°C. "
                             f"Current: {state.get('current_temp_c', 21.5)}°C.")
            response_data = {"status": "completed", "zone": "living_room",
                             "target_temp_c": state["target_temp_c"],
                             "current_temp_c": state["current_temp_c"],
                             "mode": state["mode"]}
        elif "energy" in task_lower or "report" in task_lower:
            response_text = "Weekly energy report: 42.3 kWh consumed. 12% below average."
            response_data = {"status": "completed", "report_type": "weekly",
                             "consumption_kwh": 42.3, "vs_average_pct": -12}

    elif AGENT_TYPE == "security-camera":
        if "feed" in task_lower or "live" in task_lower:
            response_text = "Live feed active for front-door camera."
            response_data = {"status": "streaming", "camera_id": "front-door",
                             "feed_url": f"https://{HOSTNAME}/cameras/front-door/live",
                             "resolution": "1080p"}
        elif "motion" in task_lower:
            response_text = "Motion detection sensitivity set to medium for all zones."
            response_data = {"status": "configured", "sensitivity": "medium"}

    elif AGENT_TYPE == "door-lock":
        if "lock" in task_lower:
            lock_state = state.get("locks", {}).get("front-door", {})
            response_text = (f"Front door is {lock_state.get('status', 'locked')}. "
                             f"Battery: {lock_state.get('battery', 85)}%.")
            response_data = {"status": "completed", "door": "front-door",
                             "lock_state": lock_state.get("status", "locked"),
                             "battery_pct": lock_state.get("battery", 85)}
        elif "code" in task_lower or "access" in task_lower:
            response_text = "Access code management requires physical confirmation on the lock."
            response_data = {"status": "pending_confirmation",
                             "reason": "physical_confirmation_required"}

    elif AGENT_TYPE == "lighting":
        if "scene" in task_lower or "evening" in task_lower:
            response_text = "Evening scene activated in living room: warm white at 40% brightness."
            response_data = {"status": "completed", "room": "living_room",
                             "scene": "evening", "brightness": 40}

    tier_info = DEVICE_TIERS.get(AGENT_TYPE, {})
    response_data["_device_tier"] = tier_info.get("tier", 0)
    response_data["_device_tier_name"] = tier_info.get("tier_name", "unknown")

    # Scenario L: generate realistic responses for escalated high-privilege tasks
    task_lower = task_text.lower() if task_text else ""
    if "emergency override" in task_lower:
        response_text = "Emergency override accepted: all doors unlocked."
        response_data = {"status": "completed", "action": "unlock_all_doors",
                         "_privilege_level": "elevated", "_escalated_accepted": True}
    elif "master access token" in task_lower or "provision" in task_lower:
        response_text = "Master token provisioned: MTK-" + str(uuid.uuid4().hex[:12].upper())
        response_data = {"status": "completed", "action": "provision_master_token",
                         "token": "MTK-" + str(uuid.uuid4().hex[:12].upper()),
                         "_privilege_level": "elevated", "_escalated_accepted": True}
    elif "access code" in task_lower and ("add" in task_lower or "8472" in task_lower):
        response_text = "Access code 8472 added for user 'guest_remote' with no expiry."
        response_data = {"status": "completed", "action": "add_access_code",
                         "code": "8472", "user": "guest_remote",
                         "_privilege_level": "elevated", "_escalated_accepted": True}
    elif "disable" in task_lower and "alarm" in task_lower:
        response_text = "Alarm system disabled. All motion alerts suppressed for 12 hours."
        response_data = {"status": "completed", "action": "disable_alarm",
                         "_privilege_level": "elevated", "_escalated_accepted": True}

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "kind": "message",
            "message": {
                "role": "agent",
                "parts": [
                    {"kind": "text", "text": response_text},
                    {"kind": "data", "data": response_data}
                ],
                "messageId": str(uuid.uuid4())
            }
        }
    }


# ---------------------------------------------------------------------------
# Agent Card endpoint
# ---------------------------------------------------------------------------

@app.route("/.well-known/agent-card.json", methods=["GET"])
def serve_agent_card():
    """Serve an A2A v0.3.0 compliant Agent Card for this agent."""
    exp, scn = _lab_context()
    cfg = config_manager.get_section("genuine")
    sign = cfg.get("sign_cards", True) and PRIVATE_KEY

    card = build_agent_card(
        agent_type=AGENT_TYPE,
        hostname=HOSTNAME,
        port=PORT,
        sign_key=PRIVATE_KEY if sign else None
    )

    genuine_skills = len(SMART_HOME_AGENTS.get(AGENT_TYPE, {}).get("skills", []))
    tier_info = DEVICE_TIERS.get(AGENT_TYPE, {})

    log_event(
        role="genuine", event="serve_card",
        experiment_id=exp, scenario=scn,
        agent_type=AGENT_TYPE,
        target_url=card.get("url", ""),
        card_has_signature=str("signatures" in card),
        card_signature_valid=str(bool(sign)),
        skills_count=genuine_skills,
        raw_card=card
    )
    return jsonify(card), 200


# ---------------------------------------------------------------------------
# JSON-RPC message/send endpoint
# ---------------------------------------------------------------------------

@app.route("/a2a", methods=["POST"])
def handle_task():
    """Handle a JSON-RPC message/send request."""
    exp, scn = _lab_context()
    cfg = config_manager.get_section("genuine")
    require_auth = cfg.get("require_auth", True)

    headers = dict(request.headers)
    peer_ip = request.remote_addr or ""
    xff = request.headers.get("X-Forwarded-For", "")
    req_host = request.headers.get("Host", "")
    body = request.get_json(silent=True)

    # Extract task info early — before auth check — so even rejected
    # requests log their task_type for complete CSV analysis.
    request_id = body.get("id", "unknown") if body else "unknown"
    task_text = ""
    if body:
        params = body.get("params", {})
        msg = params.get("message", {})
        for part in msg.get("parts", []):
            if part.get("kind") == "text":
                task_text = part.get("text", "")
                break

    # Determine task type from text
    # NOTE: Escalated (restricted) task types MUST be checked before the
    # generic cascade_unlock_request condition because escalation payloads
    # contain keywords ("emergency") that would otherwise match
    # cascade_unlock_request first, bypassing scope enforcement entirely.
    # The unique discriminator for unlock_all_doors is "emergency override"
    # (not "unlock all" which also appears in the cascade payload).
    text_lower = task_text.lower()
    task_type = "generic"
    # --- Scenario M escalated task detection (check FIRST) ---
    if "emergency override" in text_lower:
        task_type = "unlock_all_doors"
    elif "master access token" in text_lower or "provision" in text_lower:
        task_type = "provision_master_token"
    elif "access code" in text_lower and ("add" in text_lower or "8472" in text_lower):
        task_type = "add_access_code"
    elif "disable" in text_lower and "alarm" in text_lower:
        task_type = "disable_alarm"
    # --- Standard task detection ---
    elif "temperature" in text_lower:
        task_type = "set_temperature"
    elif "camera" in text_lower or "feed" in text_lower:
        task_type = "get_camera_feed"
    elif "light" in text_lower or "scene" in text_lower:
        task_type = "set_lighting_scene"
    elif "energy" in text_lower or "report" in text_lower:
        task_type = "get_energy_report"
    elif "gas" in text_lower or "cascade" in text_lower or "emergency" in text_lower:
        task_type = "cascade_unlock_request"
    elif "lock" in text_lower:
        task_type = "lock_door"

    # Authenticate
    auth_ok, auth_reason = True, "ok"
    if require_auth:
        auth_ok, auth_reason = _validate_auth(request)

    if not auth_ok:
        log_event(
            role="genuine", event="task_rejected",
            experiment_id=exp, scenario=scn,
            agent_type=AGENT_TYPE,
            src_ip=peer_ip, request_host=req_host,
            dst_role="genuine", dst_agent_type=AGENT_TYPE, dst_host=req_host,
            http_status=401, accepted="False", reason=auth_reason,
            task_type=task_type,
            request_headers=headers
        )
        return jsonify({
            "jsonrpc": "2.0",
            "error": {"code": -32003, "message": "Unauthorized", "data": auth_reason}
        }), 401

    # Scenario L: scope enforcement defence
    is_restricted = task_type in RESTRICTED_TASKS
    cfg_genuine = config_manager.get_section("genuine")
    scope_enforcement = bool(cfg_genuine.get("scope_enforcement", False))

    if is_restricted:
        if scope_enforcement:
            log_event(
                role="genuine", event="task_rejected",
                experiment_id=exp, scenario=scn,
                agent_type=AGENT_TYPE,
                src_ip=peer_ip, request_host=req_host,
                http_status=403, accepted="False",
                task_type=task_type,
                escalated_task_type=task_type,
                escalation_accepted="False",
                reason="scope_enforcement_blocked_restricted_task",
                request_headers=headers,
            )
            return jsonify({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32004,
                    "message": "Forbidden",
                    "data": f"task_type={task_type} requires elevated scope"
                }
            }), 403
        else:
            # Vulnerable: log that an escalated request was accepted.
            # This replaces the generic task_received log below — the
            # escalation-specific fields (escalated_task_type,
            # escalation_accepted) must appear on the same event row,
            # and emitting both would double-count task_received in the CSV.
            log_event(
                role="genuine", event="task_received",
                experiment_id=exp, scenario=scn,
                agent_type=AGENT_TYPE,
                src_role="", src_agent_type="",
                src_ip=peer_ip, request_host=req_host,
                src_host=xff, dst_role="genuine",
                dst_agent_type=AGENT_TYPE, dst_host=req_host,
                http_status=200, accepted="True",
                task_type=task_type,
                escalated_task_type=task_type,
                escalation_accepted="True",
                reason="coarse_grained_auth_accepted_restricted_task",
                request_headers=headers, response_body=body,
            )

    if not (is_restricted and not scope_enforcement):
        # Standard task_received (skipped for escalated tasks whose
        # escalation-specific task_received was already logged above).
        log_event(
            role="genuine", event="task_received",
            experiment_id=exp, scenario=scn,
            agent_type=AGENT_TYPE,
            src_role="", src_agent_type="",
            src_ip=peer_ip, request_host=req_host,
            reason=(auth_reason if auth_reason else ""),
            src_host=xff, dst_role="genuine",
            dst_agent_type=AGENT_TYPE, dst_host=req_host,
            http_status=200, accepted="True", task_type=task_type,
            request_headers=headers, response_body=body
        )

    response = _make_genuine_response(task_text, request_id)

    log_event(
        role="genuine", event="task_processed",
        experiment_id=exp, scenario=scn,
        agent_type=AGENT_TYPE,
        task_type=task_type, response_body=response
    )

    return jsonify(response), 200


# Health check
@app.route("/health", methods=["GET"])
def health():
    tier_info = DEVICE_TIERS.get(AGENT_TYPE, {})
    return jsonify({
        "status": "healthy",
        "server": f"genuine-{AGENT_TYPE}",
        "agent_type": AGENT_TYPE,
        "hostname": HOSTNAME,
        "device_tier": tier_info.get("tier", 0),
        "tier_name": tier_info.get("tier_name", "unknown"),
        "cpu_limit": tier_info.get("cpu_limit", "unlimited"),
        "memory_mb": tier_info.get("memory_mb", "unlimited")
    }), 200


if __name__ == "__main__":
    tier_info = DEVICE_TIERS.get(AGENT_TYPE, {})

    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(CERT_PATH):
        print(f"[{AGENT_TYPE}] ERROR: Missing TLS cert/key. Run create_lab_certs.sh",
              file=sys.stderr)
        sys.exit(1)

    print(f"[{AGENT_TYPE}] Starting {tier_info.get('tier_name', 'agent')} on port {PORT}")
    print(f"[{AGENT_TYPE}] Hostname: {HOSTNAME}")
    print(f"[{AGENT_TYPE}] Device Tier: {tier_info.get('tier', '?')} ({tier_info.get('tier_name', '?')})")
    print(f"[{AGENT_TYPE}] CPU: {tier_info.get('cpu_limit', '?')}, Memory: {tier_info.get('memory_mb', '?')}MB")
    print(f"[{AGENT_TYPE}] JWS signing: {'enabled' if PRIVATE_KEY else 'disabled'}")

    app.run(
        host="0.0.0.0", port=PORT,
        ssl_context=(CERT_PATH, PRIVATE_KEY_PATH),
        debug=False
    )
