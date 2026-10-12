# `dlpdump`

A small, **strictly read-only** inspector for a Trellix (McAfee) DLP Endpoint install.
It produces the same evidence this repository documents — straight from your machine.

> It never starts, stops, disables, uninstalls or reconfigures the agent, and it does not
> read protected policy content. Read APIs only (directory + PE version resources,
> `WinVerifyTrust`/`CryptQueryObject`, the Service Control Manager, the registry, and the
> agent's own log).

## Build

Go 1.24+, Windows, standard library only.

```bash
cd dlpdump
go test ./...
go build -o dlpdump.exe .
```

## Use

```bash
dlpdump                    # human-readable report (default)
dlpdump --format md        # Markdown catalog + state — paste into docs or an issue
dlpdump --format json      # machine-readable
dlpdump --deep             # verify the Authenticode signature of every module
dlpdump --version
```

## What it reports

- **Configuration** — agent version, computer, handler count, ePO/management state, and
  whether a global policy is present.
- **Services & kernel drivers** — the live state of `TrellixDLPAgentService` and the six
  `hdlp*` drivers, straight from the Service Control Manager.
- **Health** — last start, driver confirmations, policy-load result, ePO connectivity,
  and a de-duplicated list of errors/warnings, parsed from the agent's service log.
- **Components** — every module grouped by subsystem (core, drivers, hooks, KeyView
  filters, OCR, crypto/MIP, identity, tools, support), each core/driver/tool binary
  Authenticode-verified with its signer shown.

## How it maps to the docs

`dlpdump --format md` emits the component catalog and state tables that back the
[field guide](../README.md) and [architecture reference](../docs/ARCHITECTURE.md), so the
documentation can be regenerated against any build.

## Exit codes

`0` ok · `2` bad usage · `3` no DLP install found.

## Notes

- Trellix/McAfee DLP Endpoint on Windows only; paths are the product defaults.
- `--deep` may flag a couple of bundled third-party libraries (e.g. `libprotobuf.dll`) as
  `unsigned` — they ship without an individual Authenticode signature and are expected.
  `untrusted` (a broken signature) is the state worth investigating.
