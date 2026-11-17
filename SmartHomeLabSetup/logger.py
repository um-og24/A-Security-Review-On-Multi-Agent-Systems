# logger.py - Enhanced logging with timing instrumentation
"""
CSV-based structured logging for the A2A security testbed.
Includes verification latency measurements for defence evaluation (Stage 3).
"""

import csv
import os
import json
from datetime import datetime, timezone
from threading import Lock

LOG_DIR = os.environ["LOG_DIR"]
os.makedirs(LOG_DIR, exist_ok=True)

# Default fallback for callers that don't specify a scenario
_DEFAULT_CSV = os.path.join(LOG_DIR, "observations.csv")
_lock = Lock()
_headers_initialized = set()  # tracks which CSV files already have valid headers


def csv_path_for(scenario=None):
    """Return the CSV path for a given scenario name.
    
    Each scenario writes to its own file prefixed with its letter
    (e.g. A_baseline_vulnerable.csv, G_llm_selection_vulnerable.csv)
    so switching scenarios does not overwrite previous observations.
    """
    if not scenario or not isinstance(scenario, str) or not scenario.strip():
        return _DEFAULT_CSV
    safe = scenario.strip().replace("/", "_").replace("\\", "_")
    letter = _SCENARIO_LETTER.get(safe, "")
    prefix = f"{letter}_" if letter else ""
    return os.path.join(LOG_DIR, f"{prefix}{safe}.csv")


_SCENARIO_LETTER = {
    "baseline_vulnerable":      "A",
    "signature_defence":        "B",
    "full_defence":             "C",
    "mitm_relay":               "D",
    "mitm_full_forward":        "E",
    "transparent_proxy":        "F",
    "cascade_propagation":      "G",
    "llm_selection_vulnerable":  "H",
    "llm_selection_defended":    "I",
    "llm_injection_vulnerable":  "J",
    "session_smuggling":         "K",
    "sybil_flooding":            "L",
    "scope_escalation":          "M",
}

FIELDNAMES = [
    "ts_utc",
    "experiment_id",
    "scenario",
    "role",                 # hub | genuine | attacker | dashboard
    "event",                # see event taxonomy below
    "agent_type",           # thermostat | security-camera | door-lock | lighting
    "src_role",
    "src_agent_type",
    "src_ip",
    "src_host",
    "dst_role",
    "dst_agent_type",
    "dns_poisoning_active",       # True/False — whether hub was DNS-poisoned for this event
    "spoof_mode",                 # exaggeration | prompt_injection (attacker card build mode)
    "dst_ip",
    "dst_host",
    "dns_resolved_ip",
    "request_host",
    "target_url",
    "http_status",
    "accepted",
    "reason",
    "cert_subject",
    "card_has_signature",
    "card_signature_valid",
    "signature_kid",
    "signature_key_source",
    "skills_count",
    "skills_exaggerated",
    "task_type",
    "verification_latency_ms",
    "fetch_latency_ms",
    "push_latency_ms",
    "trial_latency_ms",
    "raw_card",
    "request_headers",
    "response_body",
    # LLM agent selection fields
    "llm_model",
    "llm_prompt_mode",
    "llm_prompt",
    "llm_selected_verified",
    "llm_selected_source",
    "llm_pulled",
    "llm_warmed",
    "llm_response_raw",
    "llm_selected_agent",
    "llm_confidence",
    "llm_latency_ms",
    "llm_cards_evaluated",
    "llm_selected_is_spoofed",
    "llm_user_request",
    # Scenario J — Session Smuggling
    "session_memory_depth",       # number of prior interactions in context when LLM was called
    "session_steering_detected",  # True if attacker steering language found in the response text
    # Scenario L — Scope Escalation
    "escalated_task_type",        # high-privilege task the attacker attempted on the genuine agent
    "escalation_accepted",        # True if the genuine agent accepted the escalated request
]

"""
Event taxonomy:
  Hub events:
    fetch_card, fetch_card_failed,
    verify_signature_ok, verify_signature_fail, verify_signature_skip,
    cert_inspect, cert_inspect_failed,
    task_send, task_send_failed, task_response,
    cascade_triggered, cascade_blocked,
    llm_agent_selected, llm_selection_no_result, llm_selection_failed,
    llm_selection_skipped

  Genuine events:
    serve_card, task_received, task_processed

  Attacker events:
    serve_spoof_card, intercept_task, tamper_response,
    relay_forward, relay_response, relay_failed, credential_captured

  Experiment events:
    experiment_start, experiment_end, scenario_start, scenario_end
"""


def _ensure_header(path=None):
    """
    Create CSV with header if it does not exist.
    If it exists with an older header, migrate it by adding any missing columns.
    """
    csv_path = path or _DEFAULT_CSV

    # Create fresh file
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES,
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()
        return

    # Check existing header and migrate if needed
    try:
        with open(csv_path, "r", newline="") as f:
            reader = csv.reader(f)
            existing_header = next(reader, None) or []
    except Exception:
        existing_header = []

    if not existing_header:
        # Corrupt or empty file, rewrite header
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES,
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()
        return

    missing = [c for c in FIELDNAMES if c not in existing_header]
    if not missing:
        return

    tmp_path = csv_path + ".migrated"
    try:
        with open(csv_path, "r", newline="") as src, open(tmp_path, "w", newline="") as dst:
            reader = csv.DictReader(src)
            writer = csv.DictWriter(dst, fieldnames=FIELDNAMES,
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()

            for row in reader:
                out = {k: (row.get(k, "") if row.get(k, "") is not None else "") for k in FIELDNAMES}
                writer.writerow(out)

        os.replace(tmp_path, csv_path)
        print(f"[logger] Migrated CSV schema for {os.path.basename(csv_path)}, added columns: {missing}")
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        print(f"[logger] CSV migration failed: {e}")


# No module-level _ensure_header() call — each scenario file
# gets its header created on first write via log_event().


def log_event(**kwargs):
    """
    Log a structured event row.

    All parameters are optional keyword arguments matching FIELDNAMES.
    Timestamp is always auto-generated.
    The file is derived from the 'scenario' kwarg so each scenario
    gets its own CSV (e.g. baseline_vulnerable.csv).
    """
    row = {field: "" for field in FIELDNAMES}
    row["ts_utc"] = datetime.now(timezone.utc).isoformat()

    for key, value in kwargs.items():
        if key in row:
            if isinstance(value, (dict, list)):
                row[key] = json.dumps(value, default=str)[:4000]
            elif value is not None:
                row[key] = str(value)[:4000].replace("\n", " ").replace("\r", "")

    path = csv_path_for(kwargs.get("scenario"))
    if path not in _headers_initialized:
        _ensure_header(path)
        _headers_initialized.add(path)

    with _lock:
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES,
                                    quoting=csv.QUOTE_ALL)
            writer.writerow(row)


def clear_logs(scenario=None):
    """Clear all log entries for a scenario, keeping the header."""
    path = csv_path_for(scenario)
    with _lock:
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES,
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()
    _headers_initialized.add(path)


def read_events(limit=100, experiment_id=None, scenario=None):
    """Read events from the scenario's CSV file with optional filters."""
    path = csv_path_for(scenario)
    events = []
    if not os.path.exists(path):
        return events
    try:
        with open(path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if experiment_id and row.get("experiment_id") != experiment_id:
                    continue
                events.append(row)
    except Exception as e:
        print(f"[logger] Error reading CSV: {e}")
    return events[-limit:]


def count_events_by(field, experiment_id=None, scenario=None):
    """Count events grouped by a field value."""
    counts = {}
    events = read_events(limit=10000, experiment_id=experiment_id, scenario=scenario)
    for e in events:
        val = e.get(field, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts
