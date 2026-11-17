# logger_service.py - Central logging service (single-writer architecture)
"""
Dedicated HTTP logging service that receives structured events from all
lab components and serialises them into per-scenario CSV files using a
single-writer, FIFO-buffered design.

Architecture
------------
Every other service (hub, attacker relay, genuine agents, dashboard) emits
events via HTTP POST to this service instead of writing CSV directly.  A
thread-safe queue buffers incoming events and a single background worker
drains them sequentially, guaranteeing:

  - No cross-container CSV write races
  - Deterministic row ordering (FIFO)
  - Safe flush behaviour

The queue carries two command types:
  - ("event", kwargs)   -> append one CSV row via logger.log_event()
  - ("clear", scenario) -> reset a scenario CSV via logger.clear_logs()

This ensures that a clear request is never processed while buffered events
from the same scenario are still pending.

Endpoints
---------
  POST /event   - accept a JSON event payload, enqueue for CSV write
  POST /clear   - enqueue a clear-logs command for a scenario
  GET  /health  - liveness probe (returns queue depth)
"""

import os
import sys
import signal
import atexit
import queue
import threading

from flask import Flask, jsonify, request as flask_request

# The original logger module does all CSV writing — we just wrap it
import logger

# ---------------------------------------------------------------------------
# FIFO buffer + background writer
# ---------------------------------------------------------------------------

_queue = queue.Queue()
_shutdown_event = threading.Event()

# Sentinel value pushed to signal the writer thread to exit
_POISON_PILL = None


def _writer_loop():
    """
    Background worker: drain the queue and write events / execute commands
    one at a time.  Runs in a single daemon thread so all CSV I/O is
    serialised without explicit file locking.
    """
    while True:
        try:
            item = _queue.get(timeout=1.0)
        except queue.Empty:
            if _shutdown_event.is_set():
                break
            continue

        if item is _POISON_PILL:
            _queue.task_done()
            break

        cmd, payload = item
        try:
            if cmd == "event":
                logger.log_event(**payload)
            elif cmd == "clear":
                logger.clear_logs(scenario=payload)
            else:
                print(f"[logger-service] Unknown command: {cmd}", file=sys.stderr)
        except Exception as exc:
            print(f"[logger-service] Writer error ({cmd}): {exc}", file=sys.stderr)
        finally:
            _queue.task_done()

    # Drain any remaining items after poison pill (graceful shutdown)
    while not _queue.empty():
        try:
            item = _queue.get_nowait()
            if item is _POISON_PILL:
                continue
            cmd, payload = item
            if cmd == "event":
                logger.log_event(**payload)
            elif cmd == "clear":
                logger.clear_logs(scenario=payload)
        except queue.Empty:
            break
        except Exception as exc:
            print(f"[logger-service] Drain error: {exc}", file=sys.stderr)


_writer_thread = threading.Thread(target=_writer_loop, daemon=True, name="csv-writer")
_writer_thread.start()


def _graceful_shutdown():
    """Signal the writer thread to finish and wait for it to drain."""
    _shutdown_event.set()
    _queue.put(_POISON_PILL)
    _writer_thread.join(timeout=8)
    if _writer_thread.is_alive():
        print("[logger-service] WARNING: writer thread did not drain in time", file=sys.stderr)


atexit.register(_graceful_shutdown)


def _handle_sigterm(*_args):
    _graceful_shutdown()
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask("logger-service")


@app.route("/event", methods=["POST"])
def receive_event():
    """Accept a JSON event payload and enqueue it for CSV writing."""
    body = flask_request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"ok": False, "error": "invalid JSON payload"}), 400

    _queue.put(("event", body))
    return jsonify({"ok": True}), 200


@app.route("/clear", methods=["POST"])
def clear_scenario():
    """Enqueue a clear-logs command for a scenario."""
    body = flask_request.get_json(silent=True) or {}
    scenario = body.get("scenario")
    _queue.put(("clear", scenario))
    return jsonify({"ok": True}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "logger",
        "queue_depth": _queue.qsize(),
        "writer_alive": _writer_thread.is_alive(),
    }), 200


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("LOGGER_PORT", "5005"))
    print(f"[logger-service] Starting single-writer logging service on port {port}")
    print(f"[logger-service] LOG_DIR = {os.environ.get('LOG_DIR', '(not set)')}")
    print(f"[logger-service] Writer thread: {_writer_thread.name} (alive={_writer_thread.is_alive()})")

    app.run(host="0.0.0.0", port=port, debug=False)
