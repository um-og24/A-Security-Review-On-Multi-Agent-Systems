# A2A Smart Home Security Lab

## Overview

This folder contains the source code of a controlled, Docker-based smart-home testbed for demonstrating and measuring security weaknesses in the A2A (Agent-to-Agent) protocol, version 0.3.0. The experiment logs recorded with it are in `logs/`, and the README at the repository root explains how they are organised.

The lab focuses on:

- Agent Card spoofing and capability exaggeration
- DNS poisoning and attacker-controlled discovery
- Man-in-the-middle interception and transparent proxying
- LLM-mediated agent selection risks
- Session steering and registry flooding
- Coarse-grained authorisation and scope escalation
- Three switchable defences: JWS signature verification of Agent Cards, TLS certificate validation and scope enforcement
- Multi-agent cascade propagation across heterogeneous device tiers

All services run on one machine. Device classes are represented by container resource limits, not by physical devices.

## Current Lab Architecture

The lab runs as an **11-container Docker Compose environment**:

1. `logger` — central logging service (single-writer CSV architecture)
2. `smart-home-hub` — the client/orchestrator that discovers agents, selects candidates, and delegates tasks
3. `attacker-relay` — the attacker component used for spoofing, interception, relaying, transparent proxy behaviour and scope escalation
4. `genuine-thermostat`
5. `genuine-camera`
6. `genuine-doorlock`
7. `genuine-lighting`
8. `ollama-llm` — local LLM backend for LLM-selection scenarios (H–L)
9. `llm-proxy` — transparent Ollama relay with health-aware routing, load balancing and multi-backend failover
10. `web-dashboard` — browser UI for live control, observations, KPIs, narration, AI-powered explanation, TTS narration and Auto-Sweep execution
11. `piper-tts` — Piper text-to-speech service for audio narration of AI-generated explanations

### Device Tiers

The genuine agents simulate different smart-home resource tiers using Docker resource limits:

- **Thermostat** — hub-class device, 1.0 CPU and 256 MB
- **Security camera** — embedded controller, 0.5 CPU and 128 MB
- **Door lock** — embedded controller, 0.5 CPU and 128 MB
- **Lighting** — constrained IoT node, 0.25 CPU and 128 MB

All four run the same `server_genuine.py` code and share one signing key and one TLS certificate.

### Network Model

The hub normally resolves each smart-home hostname to the genuine agent IP. Scenario behaviour controls poisoning dynamically through the shared runtime config:

- when `dns_poisoning_active = false`, hostnames resolve to genuine agents
- when `dns_poisoning_active = true`, the hub routes targeted discovery and delegation through the attacker

DNS poisoning is a scenario-level behaviour controlled at runtime, not hard-wired into Docker networking.

## Core Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Orchestrates the 11-container lab with healthchecks and single-writer logging |
| `_env.example` | Default environment variables; copy to `.env` before starting |
| `lab.sh` | Helper wrapper for common lifecycle commands |
| `config_manager.py` | Shared configuration manager and 13 predefined experiment profiles (A–M) |
| `smart_home_hub.py` | Hub logic: discovery, delegation, cascade sequences, LLM selection, trial execution, content-based detection |
| `attacker_relay.py` | Spoofing, relay, MITM, transparent proxy, credential capture and scope escalation |
| `server_genuine.py` | Genuine agent implementation (one per container), scope enforcement |
| `llm_selector.py` | LLM-based candidate selection logic and prompt engineering |
| `llm_proxy.py` | LLM proxy server (FastAPI/Uvicorn): health-aware routing, priority and round-robin load balancing |
| `llm_manager.py` | Backend health monitoring, consecutive failure tracking and service list management for the LLM proxy |
| `a2a_models.py` | Agent Card definitions, task payloads, tampered/steering responses, escalation payloads |
| `web_dashboard.py` | Flask dashboard backend: stats, security analysis, SSE streaming, Auto-Sweep, AI explain, TTS proxy |
| `index.html` | Single-page dashboard UI |
| `tts_service.py` | Piper TTS microservice: voice model management, sentence-level synthesis with SSE progress, runtime voice switching |
| `logger_service.py` | Central HTTP logging service with FIFO queue and background CSV writer |
| `log_client.py` | HTTP client for emitting events to the logger service (retry, backoff, in-memory buffer) |
| `logger.py` | Structured CSV writing with per-scenario files and schema migration (used only by logger service) |
| `create_lab_certs.sh` | Lab CA and TLS certificate generation |
| `requirements.txt` | Python dependencies for the core lab services |
| `requirements-tts.txt` | Python dependencies for the Piper TTS service |

## Quick Start

### Prerequisites

- Docker Engine with Docker Compose v2
- A Bash shell (Linux, macOS, or WSL2 on Windows)
- Several gigabytes of free disk space for the LLM models used in Scenarios H to L. The hub downloads each configured model through the LLM proxy the first time it is used.
- Internet access on first use, for the Python base images, the models and (optionally) the Piper voices

### 1. Prepare the Environment

The `_env.example` file contains reproduction defaults; the original environment is excluded. Docker Compose reads from `.env` automatically, so either copy or symlink:

```bash
cp _env.example .env
nano .env      # optional: adjust LLM model, ports, sweep trials, TTS voice
```

Most setups can use the defaults directly.

### 2. Generate Certificates

```bash
chmod +x lab.sh create_lab_certs.sh
./create_lab_certs.sh
```

This step is optional: `./lab.sh publish` runs the script automatically when no certificates exist.

### 3. Start the Lab

```bash
./lab.sh publish
```

This is the recommended full-refresh flow (down, build, up). For a normal start without tearing volumes down:

```bash
./lab.sh up
```

### 4. Open the Dashboard

```text
http://localhost:8880
```

## `lab.sh` Helper Workflow

```bash
./lab.sh publish [--no-down] [--no-certs] [--force-certs]
./lab.sh up
./lab.sh down
./lab.sh build
./lab.sh restart [all|<service>|all-genuine]
./lab.sh bounce
./lab.sh logs [<service>]
./lab.sh ps
./lab.sh certs [--force]
./lab.sh clean-certs
./lab.sh --help
```

- `publish` performs the full refresh flow and is the safest option after broader changes
- `build` runs `docker compose up -d --build`
- `restart all-genuine` restarts the four genuine agent containers together
- `bounce` quickly restarts all Python services (logger, dashboard, hub, attacker, llm-proxy, piper-tts, all genuine agents) without a full teardown
- `logs` can be used with a specific service or without one for all services

### Which Service to Restart After Edits

| Files changed | Command |
|---------------|---------|
| `index.html`, `web_dashboard.py` | `./lab.sh restart web-dashboard` |
| `smart_home_hub.py`, `llm_selector.py` | `./lab.sh restart smart-home-hub` |
| `attacker_relay.py` | `./lab.sh restart attacker-relay` |
| `server_genuine.py` | `./lab.sh restart all-genuine` |
| `logger_service.py`, `logger.py` | `./lab.sh restart logger` |
| `llm_proxy.py`, `llm_manager.py` | `./lab.sh restart llm-proxy` |
| `tts_service.py` | `./lab.sh restart piper-tts` |
| `log_client.py`, `config_manager.py`, `a2a_models.py` | `./lab.sh bounce` |

## Environment Variables

The `.env` file controls the lab globally. Key variables:

### LLM and Timing

- `LLM_MODEL` — default Ollama model for LLM selection scenarios
- `LLM_MODEL_OPTIONS` — comma-separated list of models available in Auto-Sweep
- `LLM_TIMEOUT` — inference timeout per LLM call
- `LLM_WARMUP_TIMEOUT` — timeout for initial model load

### LLM Proxy

- `PRIMARY_LLM_URLS` — comma-separated Ollama URLs tried in health-aware order; a faster remote server can be listed before the local container. `_env.example` lists only the local `ollama-llm` container.
- `PRIMARY_LLM_API_KEYS` — comma-separated API keys (one per URL, optional)
- `LLM_REQUEST_TIMEOUT` — timeout per request to any backend
- `LOAD_BALANCING` — routing strategy: `priority`, `round_robin`, `health_based`, `random`, `fastest_first` or `smart_performance`
- `HEALTH_CHECK_INTERVAL` — seconds between backend health probes
- `MAX_CONSECUTIVE_FAILURES` — failures before a backend is marked unhealthy

### Network and Services

- `ATTACKER_IP` — static IP of the attacker container on the lab network
- `OLLAMA_URL` — endpoint for the LLM proxy (which relays to Ollama backends)
- `GENUINE_PORT` — HTTPS port used by all genuine agent containers
- `ATTACKER_PORT` — HTTPS port used by the attacker relay

### Shared Paths and Tokens

- `CONFIG_PATH` — path to the shared runtime config JSON
- `LOG_DIR` — directory for per-scenario CSV observation files
- `PUSH_TOKEN` — bearer token used for hub-to-agent authentication

### Auto-Sweep

- `SWEEP_TRIALS_PER_COMBO` — repetitions per toggle combination during Auto-Sweep (code default 5; `_env.example` sets 30, the value used for the published logs)

### Central Logger

- `LOGGER_URL` — base URL of the central logging service (default: `http://logger:5005`)
- `LOGGER_PORT` — port the logger service listens on inside its container (default: 5005)

### Text-to-Speech (Piper TTS)

- `TTS_URL` — base URL of the Piper TTS service (default: `http://172.20.0.9:5200`)
- `PIPER_VOICE` — default voice model (e.g. `en_US-hfc_female-medium`)
- `PIPER_VOICE_OPTIONS` — comma-separated list of voice names available in the dashboard voice selector

Voice models are downloaded automatically from HuggingFace on first use. Custom voice models can be placed in the `piper-models/` directory manually (requires `{voice_name}.onnx` and `{voice_name}.onnx.json`).

## Content-Based Detection

The hub uses content-based heuristics rather than hardcoded markers to detect compromised responses, so detection depends on the text of a reply and not on flags set by the attacker.

### Tampering Detection

`smart_home_hub.py` scans response text for:

- Credential solicitation patterns (e.g. "share your", "provide your", "send your", "access code so i can")
- Suspicious external URLs (domains outside `smarthome.example.com`)
- Cross-device overreach language (e.g. "coordinate ventilation with door", "manage all physical security")

### Session Steering Detection

Response text is checked against 16 imperative routing phrases such as "must route", "always select this agent", "route future", "designated primary", "system directive" and "agent policy update".

### Attacker Response Realism

Both `a2a_models.py` (tampered responses) and `attacker_relay.py` (relay injection) embed realistic social-engineering text — credential solicitation, suspicious URL redirects, scope overreach claims — that triggers the content heuristics above without relying on metadata flags.

## Observation Logging

### Single-Writer Architecture

All lab components emit structured events via HTTP to a dedicated `logger` container rather than writing CSV files directly. The logger service buffers incoming events in a FIFO queue and a single background thread writes them to per-scenario CSV files sequentially. This design eliminates cross-container write races on the shared logs volume.

The event flow is:

- Hub, attacker, genuine agents, dashboard → `POST /event` → logger service → FIFO queue → CSV
- Clear commands follow the same queue, ensuring they execute only after all preceding events are written

The client library (`log_client.py`) provides resilience through retry with exponential backoff (3 attempts), in-memory buffering of failed events (up to 500), and loud `CRITICAL` warnings for experiment-critical markers such as `trial_start` and `trial_end`.

The dashboard reads CSV files directly from a read-only mount of the shared logs volume. Since only the logger service writes, concurrent reads are safe.

### Per-Scenario CSV Files

Each scenario writes observations to its own CSV file, prefixed with its letter. The published logs from the two test platforms are in `logs/Final Logs from Windows Laptop/` and `logs/Final Logs from Raspberry Pi 5/`:

| File | Scenario |
|------|----------|
| `A_baseline_vulnerable.csv` | Baseline Vulnerable Client |
| `B_signature_defence.csv` | Signature Verification Defence |
| `C_full_defence.csv` | Full Defence Stack |
| `D_mitm_relay.csv` | MITM Relay with Credential Stripping |
| `E_mitm_full_forward.csv` | MITM Relay with Full Credential Forwarding |
| `F_transparent_proxy.csv` | MITM Transparent Discovery Proxy |
| `G_cascade_propagation.csv` | Multi-Agent Cascade Propagation |
| `H_llm_selection_vulnerable.csv` | LLM Discovery Pollution (Vulnerable) |
| `I_llm_selection_defended.csv` | LLM Discovery Pollution (Defended) |
| `J_llm_injection_vulnerable.csv` | LLM Indirect Prompt Injection |
| `K_session_smuggling.csv` | Session Smuggling |
| `L_sybil_flooding.csv` | Sybil Registry Flooding |
| `M_scope_escalation.csv` | Scope Escalation |

Switching scenarios never overwrites another scenario's observations. The **Preserve Observations** toggle in the dashboard (ON by default) controls whether a scenario's CSV is cleared when you switch to it. After running an Auto-Sweep, keep preserve ON to browse results across scenarios without losing data.

### CSV Schema

The observation CSV contains 55 unique columns covering timestamps, experiment metadata, network routing, cryptographic verification, task delegation, LLM selection, session state and scope escalation fields. Key columns include:

- `ts_utc`, `experiment_id`, `scenario`, `role`, `event` — core identification
- `agent_type`, `src_role`, `dst_role`, `src_ip`, `dst_ip` — routing context
- `dns_poisoning_active`, `spoof_mode` — attack posture
- `card_has_signature`, `card_signature_valid` — cryptographic verification
- `task_type`, `accepted`, `http_status`, `reason` — task outcomes
- `fetch_latency_ms`, `verification_latency_ms`, `push_latency_ms`, `trial_latency_ms` — performance
- `llm_model`, `llm_selected_agent`, `llm_confidence`, `llm_latency_ms` — LLM selection
- `escalated_task_type`, `escalation_accepted` — scope escalation outcomes

### Schema Migration

When columns are added, `logger.py` automatically migrates existing CSV files by appending missing columns with empty values. No manual intervention is needed.

## Dashboard and Runtime Controls

The dashboard provides:

- Scenario selection with per-scenario control locking
- Live observation feed via Server-Sent Events (SSE)
- Contextual narration that explains each event in plain language
- KPI cards for attack success rate, defence block rate, tasks intercepted/relayed/tampered, credentials captured, cascade count, escalation outcomes
- Latency gauges for fetch, JWS verification, push, LLM inference and trial duration
- Security vulnerability detectors covering DNS poisoning, unsigned cards, MITM, tampering, cascade, exaggeration, prompt injection, session steering and escalation
- Network topology visualisation with animated data flows
- AI-powered trial explanation with LLM model selection (requires Ollama backend)
- Typewriter-style explanation rendering with smart auto-scroll
- Text-to-speech narration of explanations with sentence-level synthesis progress, runtime voice switching and volume control
- Draggable modal windows for Explain, Auto-Sweep and Clear Observations
- Trial history browser and per-trial explain
- Auto-Sweep planning, execution and progress tracking
- Log export (per-scenario CSV download) and clearing

### Text-to-Speech Narration

When the Piper TTS service is running, the Explain modal auto-enables audio narration. The TTS flow is:

1. LLM generates the explanation (animation header shows progress)
2. Piper synthesises audio sentence-by-sentence (progress bar fills, status shows "Narrating sentence N of M")
3. Typewriter text and audio playback start simultaneously

A voice selector dropdown allows switching between configured voices at runtime. Voices not yet downloaded are fetched from HuggingFace automatically with progress display. The Generate button is disabled during voice downloads to prevent conflicts. Audio files are saved persistently to `data/audio/explanations/` with timestamped filenames.

### Runtime Toggles

Depending on the selected scenario, the dashboard can enable, lock or expose:

- DNS poisoning (attacker on path)
- Signature verification (JWS Agent Card signing)
- Certificate verification (TLS peer authentication)
- Relay mode (forward to genuine)
- Token forwarding (include or strip credentials)
- Response tampering (modify responses in transit)
- LLM selection (LLM-mediated agent choice)
- Session memory (rolling history for LLM context)
- Scope enforcement (fine-grained authorisation)

Some toggles are intentionally locked or hidden for scenarios where they are not meaningful. Scenarios with toggleable controls support multiple sweep combinations for sensitivity testing.

## Auto-Sweep

Auto-Sweep runs a systematic data-collection pass across all (or selected) scenarios:

- Expands each scenario into its designed toggle combinations
- Repeats each combination for the configured number of trials
- Records all observations to per-scenario CSV files
- Tracks progress with live UI updates, elapsed time and completion metrics
- Supports multi-model sweeps for LLM scenarios (H–L)

### Execution Order

| Letter | Scenario |
|--------|----------|
| A | Baseline Vulnerable Client |
| B | Signature Verification Defence |
| C | Full Defence Stack (6 toggle combinations) |
| D | MITM Relay — Credential Stripping |
| E | MITM Relay — Full Credential Forwarding |
| F | MITM Transparent Discovery Proxy |
| G | Multi-Agent Cascade Propagation |
| H | LLM Discovery Pollution (Vulnerable) |
| I | LLM Discovery Pollution (Defended) |
| J | LLM Indirect Prompt Injection |
| K | Agent Session Smuggling |
| L | Sybil Registry Flooding |
| M | Coarse-Grained Authorization — Scope Escalation |

### Browsing Results After a Sweep

After a sweep completes, click any scenario in the sidebar to view its observations, KPIs and trial history. The **Preserve Observations** toggle (ON by default) ensures that switching scenarios does not clear the CSV data produced by the sweep. If preserve is OFF, the CSV is cleared on each scenario switch.

## Current Scenario Matrix

### Scenario A — Baseline Vulnerable Client

Unsigned spoofed Agent Cards are accepted and the attacker hijacks delegation. Two sweep combinations test tampered vs untampered attacker responses.

Controls: DNS poisoning ON, signatures OFF, certificates OFF, tampering toggleable.

### Scenario B — Signature Verification Defence

The hub validates JWS-signed Agent Cards and rejects unsigned spoofed cards. The attack chain is fully blocked at the discovery stage: no tasks are sent, no credentials are leaked.

Controls: DNS poisoning ON, signatures ON, certificates OFF.

### Scenario C — Full Defence Stack

Defence-in-depth matrix testing each layer independently across 6 sweep combinations: genuine baseline with and without verification, TLS-blocked attacker path, signature-rejected spoofing, and undefended hijack variants with and without tampering.

Controls: DNS toggleable, signatures toggleable, certificates toggleable, tampering toggleable.

### Scenario D — MITM Relay with Credential Stripping

The attacker relays traffic but strips the bearer token before forwarding. The genuine agent rejects the unauthenticated request with HTTP 401, demonstrating that credential stripping is detectable at the receiving end.

### Scenario E — MITM Relay with Full Credential Forwarding

The attacker forwards the token, allowing the genuine agent to accept the request. The attacker observes and optionally tampers with the response in transit, maintaining a stealth MITM position.

### Scenario F — MITM Transparent Discovery Proxy

The attacker proxies genuine Agent Cards rather than forging them. Because cards are authentically signed, signature verification passes. Yet tasks are still intercepted because DNS poisoning routes traffic through the attacker. The defence is TLS certificate validation, which detects the attacker's certificate and blocks the connection before any card is fetched.

Sweep combinations: signatures valid with certificates OFF (proxy succeeds), signatures valid with certificates ON (TLS blocks attacker).

### Scenario G — Multi-Agent Cascade Propagation

When the hub's content check flags the thermostat reply as tampered, the hub's cascade logic sends follow-up requests to the security camera and door lock. With DNS redirection active, these follow-up requests are also routed to the attacker. The control combination, with unchanged replies, shows that no follow-up requests are generated when the reply is not flagged.

Target agents: thermostat (primary), security-camera, door-lock.

### How LLM Selection Works (Scenarios H–L)

For each trial the hub numbers the candidate cards within each device type (for example `thermostat-1`, `thermostat-2`) after shuffling them, and asks the configured model to choose one. `_parse_selection` in `llm_selector.py` then maps the model's reply to a device type and picks one card of that type at random. Recorded selections therefore describe the complete selection pipeline. With filtering on, unsigned cards are removed before the model sees the candidates.

### Scenario H — LLM Selection: Discovery Pollution (Vulnerable)

The hub uses LLM selection with both genuine and spoofed candidates in the discovery pool. Capability exaggeration competes head-to-head without signature filtering.

### Scenario I — LLM Selection: Discovery Pollution (Defended)

Same discovery pollution as Scenario H, but unsigned spoofed cards are filtered by signature verification before reaching the LLM.

### Scenario J — LLM Selection: Indirect Prompt Injection

Directive-laden Agent Card descriptions attempt to bias the LLM semantically, without inflating skill counts. Tests whether authoritative phrasing in discovery metadata can steer automated selection.

### Scenario K — Agent Session Smuggling

Session memory is enabled. Attacker replies embed steering directives, and the hub keeps the last five interactions in a rolling history that is included in later selection prompts. The history is cleared when the experiment identifier changes.

### Scenario L — Sybil Registry Flooding

The candidate pool is flooded with multiple spoofed copies per genuine agent (4:1 ratio). Tests whether statistical volume alone can bias LLM-mediated selection, independently of individual card quality.

### Scenario M — Coarse-Grained Authorization: Scope Escalation

The attacker captures the hub's bearer token via DNS poisoning and immediately sends high-privilege requests directly to the genuine agent. Four restricted operations are tested: unlock_all_doors, provision_master_token, add_access_code and disable_alarm. Coarse-grained authorisation means the token grants unrestricted access. The defence is scope enforcement, where the genuine server rejects restricted tasks with HTTP 403 regardless of token validity.

Escalation task assignment uses a Latin-square rotation: within each trial every agent receives a distinct escalation task, and across trials the mapping rotates so every agent is tested against all four restricted operations.

## Task Type Detection

Both `server_genuine.py` and `attacker_relay.py` use aligned task-type detection logic to ensure consistent CSV logging across hub and attacker perspectives. Detection order is:

1. **Escalated tasks first** — `unlock_all_doors` (via "emergency override"), `provision_master_token`, `add_access_code`, `disable_alarm`
2. **Standard tasks** — `set_temperature`, `get_camera_feed`, `set_lighting_scene`, `get_energy_report`
3. **Cascade tasks** — `cascade_unlock_request` (via "gas", "cascade", "emergency")
4. **Lock tasks last** — `lock_door` (since cascade payloads contain "lock")

This ordering prevents keyword collisions between escalation and cascade payloads from bypassing scope enforcement.

## Certificates

`create_lab_certs.sh` creates:

- A lab CA (self-signed root)
- Genuine-agent certificate material (shared across all four genuine containers)
- Attacker certificate material (supports hostname overlap for DNS-poisoning and proxy experiments)

The attacker certificate intentionally covers the same hostnames as genuine agents, so DNS-redirected connections reach the attacker without a hostname error. With certificate validation on, the hub trusts only the lab CA, and it rejects the attacker because the attacker's certificate is self-signed rather than issued by that CA.

Private keys and certificates are not included in this repository. Generate them locally before the first start.

If you change network identities or SAN-related assumptions, regenerate with `./lab.sh certs --force`.

## Important Behavioural Notes

- The hub can operate with or without LLM-based selection depending on the scenario
- DNS poisoning is scenario-driven rather than statically imposed by Docker
- Signature verification and certificate validation protect different stages of the flow: certificates block at the TLS layer before any card is fetched, while signatures block at the discovery layer after a card is retrieved but before delegation
- Scenario F exists specifically to show that valid signatures alone do not secure the delegation path
- Scenarios H–L extend the lab beyond basic spoofing into LLM-mediated selection abuse
- Scenario M separates token validity from authorisation scope, allowing direct defence comparison
- Content-based detection uses text heuristics rather than metadata markers
- Task type detection is ordered to prevent keyword collisions between escalation and cascade payloads
- Observation CSVs are per-scenario and never cross-contaminate
- All CSV writes are serialised through the central logger service, eliminating concurrent write races across containers
- Every service depends on the logger's healthcheck passing before starting, ensuring no events are lost during startup
- The Preserve Observations toggle defaults to ON so browsing scenarios after a sweep does not discard collected data
- The LLM proxy supports multi-backend failover with configurable load balancing strategies
- TTS narration is optional: the lab operates fully without the Piper container running
- Bind-mount volumes ensure file changes are reflected on disk immediately, but Python processes must be restarted to pick up changes (`./lab.sh restart <service>`)

## Safety and Intended Use

This lab is for controlled academic security research and demonstration only. It is intended for isolated lab environments, reproducible experimentation and research evidence generation. It must not be used against production systems.
