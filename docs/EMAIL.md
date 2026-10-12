# Email integration, up close

Email is a primary exfiltration path, so DLP inspects it at send time and at rest across
Outlook and Notes. A **read-only static** teardown, companion to [`FCAGS.md`](FCAGS.md).

*Method: file inventory, version resources, the Outlook add-in bundle and Notes templates.
Nothing run or modified.*

## Outlook — send-time inspection

**[observed]**
- `fcom.exe` — **Outlook Monitor** (version resource); `fcagolh32/64` — **Outlook Hook**.
- `outlook_monitor.bundle\` — a modern Outlook **web add-in**: a `dist` folder plus a local
  TLS set (`localhost.pem`, `localhost-key.pem`, `localhost.cer`).

**[inferred]** Two integration styles coexist: the classic COM/hook add-in (`fcagolh*` +
`fcom.exe`) for desktop Outlook, and a web add-in served over a **loopback HTTPS** endpoint
(hence the bundled localhost certificate) for the modern add-in model. Messages are
inspected before send so a rule can block, encrypt or require justification.

## Lotus / HCL Notes

**[observed]** `nsfsr.dll` (KeyView NSF reader) and `NSFtemplates\` (11 items — HTML
notification templates). **[inferred]** Notes mail is supported for inspection and the
templates render user notifications for Notes.

## Mail at rest — PST/OST discovery

**[observed]** `fcpst.exe` — **Email Storage Crawler**; `pstsr.dll` / `pstxsr.dll` /
`ostsr`-class KeyView readers; the service's `fcpst`/storage-crawler and
`EmailStorageDiscovery*` registry timers. **[inferred]** The agent can crawl local PST/OST
archives (data-at-rest discovery), extract with KeyView, classify, and report matches.

## Flow

**[inferred]** Compose/send → hook or add-in captures the message + attachments → service
extracts (KeyView) and classifies → reaction (allow / block / encrypt / justify) →
incident to the console. At-rest discovery runs on a schedule rather than at send time.

## Not established

- **[unknown]** The loopback add-in's API surface and auth between add-in and agent.
- **[unknown]** Exactly which Notes/Outlook events are intercepted.
