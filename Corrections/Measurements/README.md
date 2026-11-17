# Supplementary TLS measurements (4 October 2026)

These three runs supplement the scenario logs in `SmartHomeLabSetup/logs/`. They answer two questions about TLS certificate validation that the six Scenario C configurations did not isolate:

1. Does TLS certificate validation on its own stop the redirected discovery path, with signature verification switched off?
2. How much time does certificate validation add when the hub fetches a genuine Agent Card?

## Set-up

All three runs used the Windows 11 laptop of the Windows dataset, with the testbed running in WSL2 (Ubuntu 24.04, Docker 29.1.3) and the service code unchanged. Each run loaded the Scenario C `full_defence` profile, with the genuine thermostat as the target and the attacker spoofing it with response tampering enabled. The settings were changed through the dashboard, and each run consisted of 30 single trials. Only the settings below differed.

| Run | DNS redirection to the attacker | Signature verification | TLS certificate validation | Question |
|---|---|---|---|---|
| `M47_poisoned_sigsOFF_tlsON_2026-10-04_2153` | On | Off | On | 1 |
| `M57a_clean_sigsON_tlsON_2026-10-04_2156` | Off | On | On | 2 |
| `M57b_clean_sigsON_tlsOFF_2026-10-04_2158` | Off | On | Off | 2 |

## Files

Each run has two files with the same name:

- `.csv`: the event log, in the same 55-column format as the scenario logs. A trial starts with `trial_start` and ends with `trial_end`.
- `.json`: the run settings (the switches in the table above, the profile, the target and the attacker mode), the number of trials, the start and end times, and the name of the matching CSV.

## Where to look in the logs

- Question 1 (`M47`): every trial records a `fetch_card_failed` event whose `reason` contains `CERTIFICATE_VERIFY_FAILED`. No Agent Card was received and no task was sent.
- Question 2 (`M57a` and `M57b`): compare `fetch_latency_ms` on the `fetch_card` events and `trial_latency_ms` on the `trial_end` events between the two runs. In both runs every card passed signature verification (`verify_signature_ok`) and every task completed.

The runs were made one after another on the same host, not interleaved. With validation on, the first card fetch took 413.4 ms, while no fetch in the run with validation off took longer than 83.5 ms. Comparing the runs with and without each run's first trial therefore separates this one-off delay from the steady-state difference. The absolute latencies are not directly comparable with the March scenario logs, because the container host stack was different.
