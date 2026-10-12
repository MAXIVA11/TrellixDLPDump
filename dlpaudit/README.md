# `dlpaudit`

A read-only **hardening / posture auditor** for Trellix (McAfee) DLP Endpoint. It finds
the *security holes in a DLP deployment* — the gaps that let data leak or let the agent be
switched off — and reports each with a severity and a concrete fix.

> **This is a defensive posture tool.** It assesses how well the control is deployed. It
> is strictly read-only and does **not** exploit, bypass, disable or reconfigure the
> agent.

## Build

```bash
cd dlpaudit
go test ./...
go build -o dlpaudit.exe .
```

Go 1.24+, Windows, standard library only.

## Use

```bash
dlpaudit                      # ranked findings (failures first) + posture score
dlpaudit --all                # include the checks that passed
dlpaudit --json               # machine-readable (for a SIEM or dashboard)
dlpaudit --fail-on critical   # exit non-zero only on CRITICAL failures (CI/scheduled use)
```

Exit code is non-zero when a finding at or above `--fail-on` (default `high`) fails, so it
drops cleanly into a scheduled task or pipeline.

## What it checks

Each check maps a real weakness to the component that should prevent it:

| Area | Checks |
|---|---|
| **Enforcement** | service running; a policy is actually loaded |
| **Channel coverage** | file on-access (`hdlpflt`), network (`hdlpnetmonitor`), device/USB (`hdlpdbk`), in-app hooks (`hdlphook`), driver control plane (`hdlpctrl`+`hdlpevnt`) |
| **Tamper resistance** | Access Protection on, watchdog present, uninstall protection present, policy store access-protected |
| **Integrity** | core executables/drivers/tools carry a valid Trellix signature (untrusted = possible tampering) |
| **Management** | centrally managed by ePO |
| **Hygiene** | build age, unexpected unsigned modules |

Findings roll up into a **0–100 posture score** weighted by severity, so you can track one
number over time or across a fleet.

## Example

```
 Posture score: 76/100    adequate, with gaps
 Weaknesses:    1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW

 [FAIL] CRITICAL  A policy is loaded  (ENF-02)
          No GlobalPolicy.opg was found; an agent with no policy monitors nothing.
          → fix: Deploy/assign a DLP policy from ePO ...
 [FAIL] HIGH      Device / removable-media control active (hdlpdbk)  (COV-03)
          hdlpdbk is stopped — device blocking governs USB and other removable media.
          → fix: If USB/removable control is required, load hdlpdbk ...
```

## Scope & ethics

`dlpaudit` is for administrators and researchers assessing a deployment **they own or are
authorized to assess**. It reports deployment weaknesses so they can be fixed. It is not a
tool for defeating DLP: it contains no bypass, injection or exploitation capability, and
every check is a read-only observation.
