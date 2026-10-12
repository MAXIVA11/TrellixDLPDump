# `fcags.exe` — the DLP agent service, up close

`fcags.exe` is the brain of Trellix DLP Endpoint: the SYSTEM service that holds the
policy, runs the classification engine, drives the kernel drivers, injects and talks to
the user-mode hooks, and reports incidents. Everything else in the product is a sensor or
an arm; this is the decision-maker. This note is a focused, **read-only static** teardown
of that one binary.

## Identity

| | |
|---|---|
| Path | `C:\Program Files\McAfee\DLP\Agent\fcags.exe` |
| Description | Trellix DLP Endpoint Service |
| Version | 11.14.0 (build tag `TAG_AGENT_11.14.0.414`) |
| Size | 22.8 MB, PE32+ (x64), console subsystem |
| SHA-256 | `11EDA3F423F445127542494D28CB12F8F9143695CDD85065D0FA84279680DA69` |
| Signature | Valid — **Musarubra US LLC** |
| Service | `TrellixDLPAgentService`, start **Auto**, account **LocalSystem** |
| PDB | `E:\workspace\ase_11_14_0_release_DLPW_11_14_0\…\AGENT\Binaries\Release\x64\fcags.pdb` |

**[observed]** The PDB path and `TAG_AGENT_11.14.0.414` are left in the binary and name
the vendor's internal build tree. **[observed]** The exports are `boost::serialization`
and McAfee-Agent common helpers (`ma_dl_*`, `ma_temp_buffer_*`) — the service doubles as a
loadable module for the McAfee Agent framework.

## What kind of program it is

**[observed]** A large C++ service built on three frameworks, from embedded source paths
and type names:

- **ACE** (Adaptive Communication Environment) — reactor/event-handler/timer/thread model
  (`ACE_Event_Handler`, `ACE_Thread_Mutex`, `ACE_Reactor`).
- **boost 1.84.0** — `asio` (with SSL) for async I/O, `interprocess` for shared memory,
  `serialization` for the policy/object model.
- **McAfee/Trellix common** — the `CSF` ("Common Scanning Framework") classification
  engine and the `DLPProtocol` object model, shared with the rest of the suite under
  `OPG\McAfeeCommon`.

**[inferred]** It is an event-driven service: an ACE reactor dispatches events from the
drivers, the hooks, timers and the network, and handlers evaluate them against policy.

## Capability map (from the import table)

The APIs it links tell you what it is allowed to do. Selected, security-relevant imports:

| DLL | What it enables |
|---|---|
| `KERNEL32` — `DeviceIoControl`, `CreateFileW` | **Talk to the six kernel drivers** via their device objects (below). |
| `KERNEL32` — `CreateNamedPipeW`, `ConnectNamedPipe` | Named-pipe IPC with the per-session agent and hooks. |
| `KERNEL32` — `CreateRemoteThread`, `WriteProcessMemory` | **Participate in injecting the hooks** into target processes. |
| `ADVAPI32` — `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `CreateProcessAsUserW` | Drop from SYSTEM into a **user session** to launch `fcag.exe` and act as the user. |
| `ADVAPI32` — `SetSecurityDescriptorDacl/Sacl`, `SetKernelObjectSecurity` | **Lock down its own objects** (self-protection). |
| `ADVAPI32` — `OpenSCManagerW`, `CreateServiceW`, `RegisterServiceCtrlHandlerExW` | Manage services/drivers; run as a service. |
| `WINTRUST` — `WinVerifyTrust`, `WinVerifyTrustEx` | **Authenticode-verify** modules/content before trusting them. |
| `bcrypt`, `CRYPT32` | Hashing, DPAPI, certificate handling. |
| `WINHTTP`, `WS2_32`, `MSWSOCK` | HTTP(S) to the management server; sockets. |
| `fwpuclnt` | **Windows Filtering Platform** user-mode — configure the network callout. |
| `SETUPAPI`, `fcdrvins.dll` | Enumerate devices / install the drivers (device control). |
| `IPHLPAPI`, `DNSAPI`, `MPR`, `NETAPI32`, `ACTIVEDS` | Network, DNS, shares, and **Active Directory** lookups. |
| `WTSAPI32`, `USERENV`, `Secur32` | Session enumeration, user profiles, SSPI. |
| `OLEACC`, `USER32` | UI Automation / accessibility (window & control context for screen/clipboard rules). |
| `EntraIdBridge.dll` | Microsoft Entra identity. |

> There are **no delay imports**; everything is bound up front.

## How it drives the kernel drivers

**[observed]** `fcags.exe` opens these NT device objects with `CreateFileW` and issues
`DeviceIoControl` to them — this is the service↔driver control channel:

| Device object | Driver | Purpose |
|---|---|---|
| `\\.\DlpMiniFileFilter` | `hdlpflt.sys` | file minifilter control |
| `\\.\DLPNetMonitor` | `hdlpnetmonitor.sys` | WFP network callout |
| `\\.\DevBkCtrl` | `hdlpdbk.sys` | device-blocking control |
| `\\.\DlpEventManager` | `hdlpevnt.sys` | kernel→service event channel |
| `\\.\FFShare`, `\\.\FFtft` | `hdlpflt.sys` | file-filter shared / transfer interfaces |

**[observed]** It tunes the drivers through registry keys such as
`…\Services\hdlpctrl\DeviceBlockingRules`, `…\hdlpdbk\IphoneBlockMode`,
`…\hdlpflt\ForceAgentDevParams`, and shared-memory counters
`…\hdlpevnt\SM\cnt`, `…\hdlphook\SM\hcnt`. The function
`AgentService::installHdlpflt` installs and starts the minifilter on demand.

## The classification engine (CSF)

**[observed]** The "Common Scanning Framework" (`CSF::…`) is how content becomes a
verdict. Evidenced components:

- **Dictionaries** — `Dictionary` / `DictionaryLetterNode` (a trie / Aho-Corasick keyword
  matcher) held in shared memory.
- **Regular expressions** — `CSF::RegExSearcher` built on Google **RE2** (`addRe2`,
  `RegExSearcherCache`), with proximity scoring (`getProximities`).
- **Exact Data Matching (EDM)** — `ExactDataFingerprintsService`,
  `ExactDataFingerprintsSearcher::loadFingerprints`, `determineEDMVersion`; fingerprints
  are loaded from a package into shared memory (`allocateSharedMemory`).
- **Registered Documents** — `RegisterDocumentsService` keeps `FileHash`/`DbSignature`
  maps (document fingerprints) so known files are recognised.

**[observed]** These live in named shared-memory segments — `CSFClassification`,
`ExactDataFingerprints`, `ExactDataMatchings`, `EnhancedExactDataMatchings`,
`RegisteredDocuments`, `Dictionaries` — registered under
`HKLM\SOFTWARE\McAfee\DLP\Agent\SharedMemory`. **[inferred]** The service builds these
once and the hooks/extractors map them read-only, so every process classifies against the
same tables without duplicating them.

## IPC & shared state

**[observed]** Two mechanisms:

1. **Named pipes** (`CreateNamedPipeW`/`ConnectNamedPipe`) — request/response with the
   per-session `fcag.exe` and the injected hooks.
2. **boost::interprocess `managed_windows_shared_memory`** — the large shared tables
   above (classification data, registered-document hashes, EDM fingerprints), keyed by
   `FileHash`, `DbSignature`, `_GUID`.

**[inferred]** Hot-path classification data is shared memory (fast, zero-copy); control
and events are pipes/DeviceIoControl.

## Internal subsystems

**[observed]** The service is organised into handler/manager classes. Ranked by how often
each name appears in the binary (a rough proxy for surface area):

| Subsystem | What it does |
|---|---|
| `DeviceBlockingHandler` / `DeviceBlockingManager` | Removable-media & device-class control; adds/removes the `hdlpdbk` filter per device by compatibility ID. |
| `WFPCalloutManager` | Programs and manages the network (WFP) callout — network DLP. |
| `ConfigurationHandler` | Applies agent configuration (incl. browser extension enforcement). |
| `AgentService` | Service lifecycle, driver checks, self-remediation, session login handling. |
| `ReputationManager` | File/URL reputation. |
| `PolicyDispatcher` | Reads and distributes the policy (`GlobalPolicy.opg`). |
| `SystemConfigurationManager` | ePO connectivity state machine, system config. |
| `UrlMonitor` / `URLUpdateEventHandler` | Web-destination monitoring. |
| `IncrementalDataDistributionService` | Incremental policy/classification data updates. |
| `RegisterDocumentsService` / `ExactDataFingerprintsService` | Document fingerprints & EDM. |
| `DataProtectionEngine` / `ProtectionRuleEngine` | Evaluate protection rules → reactions. |
| `CFileReplicatorService` | Evidence copies of offending content. |
| `DriveMediumService` / `FileSharingService` / `DFSResolvingService` | Volume, share and DFS resolution. |
| `CitrixPolicyManager` | Citrix/VDI multi-session support. |
| `PolicyInjectionManager` | Decides where the user-mode hooks get injected (works with `hdlphook`; see `CTDllInjection`). |
| `ORegistryKeyMonitor` | Watches registry keys for config/trigger changes. |
| `CertificateService` | Certificate handling for secure comms / signing. |

## Policy & object model

**[observed]** The wire/object model is the `DLPProtocol` namespace — e.g. `CTContent`,
`CTContentTags`, `CTReactionList`, `CTLocation`, `CTDllInjection`,
`BaseProtectionRuleEvent`, `BaseDeviceRuleEvent`, `CfgAgentConfiguration`,
`AsRemovableDeviceParameters` — carried with `boost::serialization`. **[inferred]** The
compiled policy (`GlobalPolicy.opg`) and the messages between service, drivers and hooks
are boost-serialized `DLPProtocol` objects. **[unknown]** the exact container framing (the
`.opg` was not opened).

## Management & network

**[observed]** `WINHTTP` + boost::asio SSL for HTTPS to the management plane;
`SystemConfigurationManager` runs the ePO connectivity state machine; discovery/at-rest
config names SharePoint handlers, `ScanRepositories`, `DiscoverySummaryReport`,
`MatchedItemsInEpo`, `ReportInDLPConsole`. **[inferred]** Incidents, evidence and results
flow to ePO/the DLP console; at-rest discovery can crawl file shares and SharePoint.

## Process-injection role

**[observed]** `fcags.exe` imports `CreateRemoteThread` + `WriteProcessMemory` and has a
`PolicyInjectionManager` plus a `CTDllInjection` policy type; the hooks are loaded by
`hdlphook.sys`. **[inferred]** The service decides *which* processes to hook and
cooperates with the injection driver to place the user-mode hooks — consistent with the
`Madshi driver installed` (madCodeHook) line in the runtime log.

## What is **not** established (read-only limits)

- **[unknown]** The `DeviceIoControl` IOCTL codes and the pipe/shared-memory message
  schemas (would need dynamic tracing).
- **[unknown]** The `.opg` policy container format and the EDM fingerprint package format.
- **[unknown]** Exact threading/sequencing inside the service and which paths call out to
  the network.
- The many embedded **CLSIDs/IIDs** were catalogued but not all resolved; the confirmed
  COM relationship is the **SFP Repair** class the service exposes (see
  [`ARCHITECTURE.md`](ARCHITECTURE.md)).

---

*Method: static only — PE header/import/export parsing, string and symbol extraction, the
service registry key, and the agent's own log. The binary was not run under analysis, not
modified, and nothing in the service was changed.*
