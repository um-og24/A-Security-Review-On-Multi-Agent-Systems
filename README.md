# A Security Review on Multi-Agent Systems: A2A Smart Home Testbed

This repository contains the testbed, experiment logs and supporting data of a security study of the Agent-to-Agent (A2A) protocol, version 0.3.0, in a simulated smart home. The study examines four kinds of attack against an A2A hub and its device agents:

- forged (unsigned) Agent Cards that impersonate genuine devices
- man-in-the-middle interception after DNS redirection
- manipulation of LLM-based agent selection
- reuse of a captured bearer token for privileged operations

It also evaluates three defences: JWS signature verification of Agent Cards, TLS certificate validation, and scope enforcement on the device agents.

## Repository layout

| Path | Contents |
|---|---|
| `SmartHomeLabSetup/` | Testbed source code: Docker Compose file, hub, attacker, genuine device agents, LLM proxy, logger and web dashboard. See `SmartHomeLabSetup/README.md`. |
| `SmartHomeLabSetup/logs/Final Logs from Windows Laptop/` | The 13 scenario logs (CSV) recorded on a Windows 11 laptop on 11 March 2026 |
| `SmartHomeLabSetup/logs/Final Logs from Raspberry Pi 5/` | The same 13 scenario logs recorded on a Raspberry Pi 5 (16 GB) on 12 March 2026 |
| `Charts/` | Data workbook and images of the seven results charts (see below) |
| `Corrections/Measurements/` | Three supplementary TLS measurements of 4 October 2026 (see the README in that folder) |

## Experiment scenarios

Each scenario is a predefined profile in `SmartHomeLabSetup/config_manager.py`. Every configuration was run for 30 trials on each platform.

| Scenario | What it tests | Varied in the runs | Trials per platform |
|---|---|---|---|
| A | Hub accepts a forged, unsigned Agent Card served after DNS redirection | Attacker reply tampered or unchanged | 60 |
| B | The same attack with JWS signature verification on | None | 30 |
| C | Combinations of DNS redirection, signature verification and TLS validation | Six configurations | 180 |
| D | Man-in-the-middle relay that strips the bearer token | None | 30 |
| E | Man-in-the-middle relay that forwards the bearer token | Relayed reply tampered or unchanged | 60 |
| F | Transparent proxy that relays genuine signed Agent Cards | TLS validation off or on | 60 |
| G | Tampered thermostat reply that makes the hub send follow-up requests to the camera and door lock | Cascade-triggering run and control run | 60 |
| H | LLM selection between genuine and forged cards with exaggerated capabilities | Five LLM models | 150 |
| I | As H, with unsigned cards filtered out before selection | Five LLM models | 150 |
| J | LLM selection with instructions embedded in forged card descriptions | Five models, filtering off or on | 300 |
| K | LLM selection with a rolling history that can carry steering text | Five models, filtering off or on | 300 |
| L | LLM selection with four forged cards for every genuine card | Five models, filtering off or on | 300 |
| M | Reuse of a captured token for four restricted operations | Scope enforcement off or on | 60 |

The five models are `qwen2.5:1.5b`, `llama3.2:3b`, `mistral:7b`, `gemma3n:e4b` and `dolphin-llama3:8b`, served through Ollama.

## Reading the logs

- Each CSV holds one scenario. Each row is one event logged by the hub, the attacker or a genuine agent, using a common 55-column schema (described in `SmartHomeLabSetup/README.md`).
- A trial starts with a `trial_start` event and ends with a `trial_end` event. The trial number is in the `reason` column (for example `trial_id=31`), and the trial duration is in `trial_latency_ms`.
- Each configuration of a scenario starts with a `sweep_combo_start` event.
- Bearer tokens, credentials and household requests in the logs are synthetic test values.

Two points matter when interpreting the results:

- Scenarios A to G and M are configuration-driven: the outcome is fixed by which controls are switched on. The 30 repetitions show that the outcome was consistent and give latency distributions; they are not estimates of how often the attack succeeds elsewhere.
- In Scenarios H to L the hub's parser (`_parse_selection` in `llm_selector.py`) reduces the model's answer to a device type and then picks a card of that type at random. The recorded selections therefore describe the whole selection pipeline, not the model's preference alone. The logs record which model was used but not which inference server answered each request.

## Charts

`Charts/Chapter_5_Figure_Data.xlsx` holds the values plotted in the charts, with one sheet per chart or table:

| File | Content |
|---|---|
| `Chart_1_Attack_Outcomes` | Recorded attack outcomes, Scenarios A to G, on each platform |
| `Chart_2_Trial_Latency` | Mean trial latency on each platform, Scenarios A to G |
| `Chart_3_Credential_Captures` | Credential captures per trial, with the Scenario G firing and control runs separately |
| `Chart_4_Pipeline_Selected_Attacker_Cards` | Share of trials in which an attacker card was selected, Scenarios H to L, with 95% Wilson intervals |
| `Chart_5_Pipeline_Outcomes_by_Model_Windows` | The same per model, Windows, without filtering |
| `Chart_6_Scope_Escalation` | Scope escalation outcomes on each platform |
| `Chart_7_Trial_Latency_All_Scenarios_Windows` | Mean trial latency across all 13 scenarios on Windows |

Each chart is provided as a PNG image. Charts 1, 2, 3 and 7 also have an SVG source.

## Running the testbed

Requirements: Docker with Docker Compose v2 and a Bash shell (Linux, macOS or WSL2 on Windows). The LLM scenarios need several gigabytes of disk space for the models, which the hub downloads through the LLM proxy the first time they are used.

```bash
cd SmartHomeLabSetup
cp _env.example .env
bash lab.sh publish
```

`lab.sh publish` generates the laboratory certificates with `create_lab_certs.sh` if none exist, then builds and starts the eleven containers. Open the dashboard at `http://localhost:8880`, choose a scenario and run single trials, or use Auto-Sweep to run every configuration. New logs are written to `SmartHomeLabSetup/logs/`.

Private keys, certificates and the original environment file are not included. The certificate script generates a fresh laboratory CA and certificates, and `_env.example` provides working defaults, including 30 trials per configuration.

## Intended use

The testbed is intended for controlled security research in an isolated laboratory network. It contains working attack components and must not be used against systems without permission.
