# log_client.py - HTTP client for the central logger service
"""
Drop-in replacement for direct ``logger.log_event()`` / ``logger.clear_logs()``
calls.  Every service imports this module instead of ``logger`` and emits
events over HTTP to the dedicated logging container.

Usage
-----
    from log_client import log_event, clear_logs

    log_event(role="hub", event="fetch_card", scenario="baseline_vulnerable", ...)
    clear_logs(scenario="baseline_vulnerable")

The function signatures mirror the originals so existing call sites require
only an import change.

Resilience
----------
  - Retries each request up to 3 times with exponential backoff (0.2s, 0.5s, 1.0s).
  - On total failure, buffers the event in memory (up to 500 items) and
    attempts to flush the buffer on the next successful call.
  - Critical experiment markers (trial_start, trial_end, sweep_combo_start,
    sweep_combo_end, scenario_start, scenario_end, experiment_start,
    experiment_end) emit a loud CRITICAL warning to stderr on failure so
    they are impossible to miss in ``docker logs``.

Environment
-----------
    LOGGER_URL  -  Base URL of the logger service (default: http://logger:5005)
"""

import os
import sys
import json
import time
import threading
from collections import deque

import requests

_LOGGER_URL = os.environ.get("LOGGER_URL", "http://logger:5005").rstrip("/")
_EVENT_ENDPOINT = f"{_LOGGER_URL}/event"
_CLEAR_ENDPOINT = f"{_LOGGER_URL}/clear"

# Reuse a Session for connection pooling across calls within the same process
_session = requests.Session()

# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

_MAX_RETRIES = 3
_BACKOFF_SCHEDULE = (0.2, 0.5, 1.0)  # seconds between attempts

# ---------------------------------------------------------------------------
# In-memory buffer for events that failed after all retries
# ---------------------------------------------------------------------------

_BUFFER_MAX = 500
_buffer = deque(maxlen=_BUFFER_MAX)
_buffer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Critical event markers — failures on these are reported loudly
# ---------------------------------------------------------------------------

_CRITICAL_EVENTS = frozenset({
    "trial_start",
    "trial_end",
    "sweep_combo_start",
    "sweep_combo_end",
    "scenario_start",
    "scenario_end",
    "experiment_start",
    "experiment_end",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _post_with_retry(url, payload, timeout=5):
    """
    POST JSON to *url* with up to ``_MAX_RETRIES`` attempts.

    Returns True on success (HTTP 200), False if all attempts failed.
    """
    last_exc = None
    for attempt in range(_MAX_RETRIES):
        try:
            resp = _session.post(url, json=payload, timeout=timeout)
            if resp.status_code == 200:
                return True
            # Non-200 but the server responded — log and treat as failure
            print(
                f"[log_client] Logger returned {resp.status_code} "
                f"(attempt {attempt + 1}/{_MAX_RETRIES}): {resp.text[:200]}",
                file=sys.stderr,
            )
        except Exception as exc:
            last_exc = exc

        # Backoff before next attempt (skip after final attempt)
        if attempt < _MAX_RETRIES - 1:
            time.sleep(_BACKOFF_SCHEDULE[attempt])

    # All attempts exhausted
    if last_exc:
        print(
            f"[log_client] All {_MAX_RETRIES} attempts failed ({last_exc})",
            file=sys.stderr,
        )
    return False


def _flush_buffer():
    """
    Try to send buffered events that failed previously.

    Called after a successful ``log_event`` delivery — if we can reach the
    logger now, chances are the buffered items will go through too.  Stops
    at the first failure to avoid blocking the caller for too long.
    """
    with _buffer_lock:
        while _buffer:
            payload = _buffer[0]
            try:
                resp = _session.post(_EVENT_ENDPOINT, json=payload, timeout=3)
                if resp.status_code == 200:
                    _buffer.popleft()
                else:
                    break  # logger is struggling, stop flushing
            except Exception:
                break


def _format_fallback(payload):
    """Compact JSON string of *payload* for stderr output."""
    try:
        return json.dumps(payload, default=str)[:1000]
    except Exception:
        return str(payload)[:1000]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def log_event(**kwargs):
    """
    Send a structured event to the central logger service.

    Accepts the same keyword arguments as ``logger.log_event()`` — the
    logger service will write them into the appropriate scenario CSV.

    On total failure after retries the event is buffered in memory and a
    warning is printed to stderr.  Critical experiment markers produce a
    louder ``CRITICAL`` warning.
    """
    ok = _post_with_retry(_EVENT_ENDPOINT, kwargs)

    if ok:
        # Opportunistically drain any previously buffered events
        if _buffer:
            _flush_buffer()
        return

    # --- Delivery failed after all retries ---

    event_name = kwargs.get("event", "")
    is_critical = event_name in _CRITICAL_EVENTS

    # Buffer for later delivery
    with _buffer_lock:
        _buffer.append(kwargs)
        buffered = len(_buffer)

    if is_critical:
        print(
            f"[log_client] *** CRITICAL *** Failed to deliver critical marker "
            f"'{event_name}' after {_MAX_RETRIES} attempts — buffered "
            f"({buffered}/{_BUFFER_MAX}). Event: {_format_fallback(kwargs)}",
            file=sys.stderr,
        )
    else:
        print(
            f"[log_client] Event '{event_name}' buffered after {_MAX_RETRIES} "
            f"failed attempts ({buffered}/{_BUFFER_MAX}): "
            f"{_format_fallback(kwargs)}",
            file=sys.stderr,
        )


def clear_logs(scenario=None):
    """
    Ask the central logger service to clear a scenario's CSV file.

    The clear command is enqueued into the same FIFO as events, so it
    is guaranteed to execute only after all previously accepted events
    have been written.

    Uses the same retry logic as event delivery.
    """
    ok = _post_with_retry(_CLEAR_ENDPOINT, {"scenario": scenario})
    if not ok:
        print(
            f"[log_client] *** CRITICAL *** Failed to clear logs for "
            f"scenario={scenario} after {_MAX_RETRIES} attempts",
            file=sys.stderr,
        )
