# Trellix DLP Endpoint — Architecture Reference

A professional architecture description of Trellix (McAfee) DLP Endpoint, derived from a
read-only teardown of a live **11.14.0.4142** install on Windows 11. The companion
[`README.md`](../README.md) is the component field guide; this document is the design
reference: layers, data flows, trust boundaries, and deployment topology.

Each statement is tagged **[observed]** (read directly from the binaries, registry, SCM
or logs), **[inferred]** (reasoned from observations), or **[unknown]** (not established
by read-only means).

---

## 1. Design principles

Three principles explain almost every component:

1. **Intercept where the data is readable.** Content is classified in **user mode**,
   inside the application, where it is still plaintext — before TLS, before archiving,
   before the clipboard is consumed. *[inferred from the hook set + KeyView placement]*
2. **Enforce where the application cannot escape.** The hard guarantees live in **kernel
   drivers** (file minifilter, network callout, device blocking) that an app cannot go
   around. *[observed: six `hdlp*.sys` drivers]*
3. **Separate brain from hands.** One **service** (`fcags.exe`) holds policy and
   classification; thin **hooks**, **drivers** and **per-session agents** do the
   intercepting and enforcing and report back. *[observed: service + driver + hook split]*

---

## 2. Layered model

```mermaid
flowchart TB
    subgraph CH["① Monitored channels"]
        direction LR
        br[Browsers]:::ch
        em[Email]:::ch
        rm[USB / MTP]:::ch
        pr[Print]:::ch
        cb[Clipboard]:::ch
        sc[Screen]:::ch
        cl[Cloud]:::ch
        nw[Network]:::ch
        fi[Files]:::ch
    end

    subgraph UM["② User-mode hooks (injected by hdlphook.sys)"]
        direction LR
        hks["fcag* hooks<br/>clipboard · print · screen · cloud · file · browser · Outlook"]:::um
        nmh["Native Messaging Host<br/>fcnm.exe / fcnmtub.exe"]:::um
    end

    subgraph SVC["③ Agent service — fcags.exe (SYSTEM)"]
        direction LR
        pol[Policy engine]:::svc
        cls["Classification<br/>KeyView · OCR · regex · dictionaries"]:::svc
        lbl["Labels & crypto<br/>MIP/Purview · RMS · OpenSSL"]:::svc
        idn["Identity<br/>Entra / MSAL"]:::svc
        evt[Evidence & event reporting]:::svc
    end

    subgraph KN["④ Kernel drivers (ring 0)"]
        direction LR
        flt["hdlpflt.sys<br/>file minifilter"]:::kn
        net["hdlpnetmonitor.sys<br/>WFP callout"]:::kn
        dbk["hdlpdbk.sys<br/>device blocking"]:::kn
        hook["hdlphook.sys<br/>injection"]:::kn
        ctrl["hdlpctrl.sys<br/>controller"]:::kn
        ev["hdlpevnt.sys<br/>event bus"]:::kn
    end

    subgraph MG["⑤ Management plane"]
        direction LR
        epo[ePolicy Orchestrator]:::mg
        ma[McAfee/Trellix Agent]:::mg
        ps["Policy store<br/>GlobalPolicy.opg"]:::mg
    end

    CH --> UM --> SVC
    KN <--> SVC
    CH -.file/net events.-> KN
    MG <--> SVC

    classDef ch fill:#eef2fb,stroke:#9fb4e0,color:#1a2a4a;
    classDef um fill:#ffffff,stroke:#c0c8d6,color:#1a2230;
    classDef svc fill:#eaf1ff,stroke:#7aa7ef,color:#123a86;
    classDef kn fill:#fff1e8,stroke:#e2995f,color:#8a3b12;
    classDef mg fill:#ecfaf0,stroke:#7cc795,color:#1d6b39;
```

A rendered, print-quality version is [`architecture.svg`](architecture.svg).

---

## 3. The layers in detail

### ① Monitored channels *[observed]*
The egress and in-use channels the product cares about: browsers, Outlook/Notes email,
removable storage and MTP devices, local/network printing, clipboard, screen capture,
cloud/web uploads, raw network, and files on access.

### ② User-mode hooks *[observed set; [inferred] mechanism]*
`hdlphook.sys` injects the `fcag*` hook DLLs (shipped as 32- and 64-bit pairs) into
running processes. Each hook understands one channel (see the README's hook table). The
service log line `Madshi driver installed.` indicates the injection is built on the
**madCodeHook** library. The browser extensions reach the agent through the **Native
Messaging Host** (`fcnm.exe`/`fcnmtub.exe`) over Chrome native-messaging stdio.

### ③ Agent service *[observed process; [inferred] internal split]*
`fcags.exe` runs as the SYSTEM service `TrellixDLPAgentService`. It contains:

- **Policy engine** — evaluates rules, reactions and exceptions against each event.
- **Classification** — drives KeyView extraction and OCR (hosted out-of-process by
  `fcagte.exe`) and applies keyword/dictionary/regex/fingerprint matching.
- **Labels & crypto** — MIP/Purview sensitivity labels, RMS decryption, OpenSSL/FIPS for
  encryption reactions.
- **Identity** — Entra/MSAL user and tenant resolution.
- **Evidence & event reporting** — builds incidents and evidence copies for the console.

`fcag.exe` is the per-session arm that enforces in the user's desktop context and shows
justification/notification prompts.

### ④ Kernel drivers *[observed]*
See the README table. Load characteristics confirmed from the registry:

| Driver | Start | Type | Group / Altitude |
|---|---|---|---|
| `hdlpflt` | boot (1) | file system (2) | *FSFilter Content Screener*, altitude **261200** |
| `hdlpdbk` | demand (3) | kernel (1) | device blocking |
| `hdlpnetmonitor` | demand (3) | kernel (1) | WFP callout |
| `hdlphook` | demand (3) | kernel (1) | injection |
| `hdlpctrl` | demand (3) | kernel (1) | controller |
| `hdlpevnt` | demand (3) | kernel (1) | event bus |

### ⑤ Management plane *[observed standalone; [inferred] managed]*
Normally ePO authors and pushes policy and collects incidents through the McAfee/Trellix
Agent transport. The compiled policy is cached as `GlobalPolicy.opg`. On the analyzed
host there was **no ePO server configured** (`AgentOnline=0`, no `AgentGUID`), so the
agent idled with no active policy — visible as repeating
`ePO connection information is missing` warnings in the log.

---

## 4. Decision data flow

```mermaid
flowchart LR
    A["User action<br/>(upload / copy / print / save)"] --> B{Intercepted}
    B -->|user mode| C[Relevant fcag* hook]
    B -->|kernel| D["hdlpflt / hdlpnetmonitor / hdlpdbk"]
    C --> E[fcags.exe]
    D --> E
    E --> F["Extract text<br/>KeyView + OCR"]
    F --> G["Classify<br/>keywords · regex · dictionaries · fingerprints · labels"]
    G --> H{Policy match?}
    H -->|no| I[Allow]
    H -->|yes| J["Apply reaction<br/>block · encrypt · justify · monitor"]
    J --> K["Report incident + evidence → ePO"]

    classDef n fill:#eef2fb,stroke:#9fb4e0,color:#16223a;
    class A,C,D,E,F,G,I,J,K n;
```

**[inferred]** overall; each node is **[observed]** as a present capability (hooks,
drivers, KeyView, classification data, reaction types, evidence reporting), but the exact
ordering inside `fcags.exe` is not visible from read-only inspection.

---

## 5. Trust boundaries & self-protection

```mermaid
flowchart TB
    subgraph ring0["Ring 0 — kernel (highest trust)"]
        d["hdlp* drivers"]
    end
    subgraph system["SYSTEM service"]
        s["fcags.exe + watchdog + Access Protection"]
    end
    subgraph user["User session"]
        a["fcag.exe + injected hooks"]
        app["Monitored apps"]
    end
    d <--> s
    s <--> a
    a --> app
    s -. protects .-> d
    s -. protects .-> a

    classDef k fill:#fff1e8,stroke:#e2995f,color:#8a3b12;
    classDef y fill:#eaf1ff,stroke:#7aa7ef,color:#123a86;
    classDef u fill:#ffffff,stroke:#c0c8d6,color:#1a2230;
    class d k; class s y; class a,app u;
```

**[observed]** Self-protection spans all three rings: `UninstallProtection.exe`, the
`fcagswd.exe` watchdog + per-session `AgentWatchDog`, kernel-backed **Access Protection**
of the agent's files/services/registry, and an **ACL-locked policy store** that a normal
user cannot even list. **[inferred]** The intent is that neither a standard user nor a
compromised application can silently disable the agent or read/alter its policy.

---

## 6. Deployment topology

```mermaid
flowchart LR
    subgraph server["Management (server side)"]
        epo["ePolicy Orchestrator<br/>policy authoring · incident console"]
        db[("Policy & incident DB")]
        epo --- db
    end
    subgraph ep1["Endpoint A"]
        ag1["Trellix Agent → DLP agent"]
    end
    subgraph ep2["Endpoint B"]
        ag2["Trellix Agent → DLP agent"]
    end
    epo -- policy down --> ag1
    epo -- policy down --> ag2
    ag1 -- incidents/evidence up --> epo
    ag2 -- incidents/evidence up --> epo

    classDef s fill:#ecfaf0,stroke:#7cc795,color:#1d6b39;
    classDef e fill:#eef2fb,stroke:#9fb4e0,color:#16223a;
    class epo,db s; class ag1,ag2 e;
```

**[inferred]** from the management-plane components and the agent's ePO connectivity
state machine; the server side was not present on the analyzed host.

---

## 7. What is *not* established (read-only limits)

- **[unknown]** The internal format of `GlobalPolicy.opg` and `IncrementalData` (the
  policy store is encrypted and ACL-locked; it was not opened).
- **[unknown]** The exact driver↔service control protocol and hook↔service IPC.
- **[unknown]** The precise evaluation order and threading inside `fcags.exe`.
- **[unknown]** Which classification/telemetry paths make outbound network calls, and
  behaviour that only appears under active ePO management or with a deployed policy.

These would require dynamic analysis or vendor documentation and were intentionally left
untouched to keep this a read-only study.

---

## 8. Component → responsibility map (quick index)

| Layer | Files | Responsibility |
|---|---|---|
| Kernel | `hdlpflt/dbk/netmonitor/hook/ctrl/evnt.sys` | Interception & enforcement in ring 0 |
| Service | `fcags.exe`, `fcag.exe`, `fcagswd.exe` | Policy, classification, enforcement, self-protection |
| Extraction | `fcagte.exe`, `*sr.dll`, `kp*rdr.dll`, `ocr.dll` | Turn any file/image into text |
| Hooks | `fcag*{32,64}.dll` | See content in-app across every channel |
| Email | `fcom.exe`, `fcagolh*`, `fcpst.exe`, `outlook_monitor.bundle`, `NSFtemplates` | Outlook/Notes inspection & PST discovery |
| Browser | `fcnm.exe`, `fcnmtub.exe`, extensions, `fcagchrome/ff/iep*` | Browser upload inspection |
| Labels/crypto | `mip_*.dll`, `TitusSDKInterface.dll`, `cryptographyservices.dll`, `fips.dll` | Sensitivity labels, RMS, encryption |
| Identity | `msalruntime.dll`, `Microsoft.Identity.*`, `EntraIdBridge.dll` | User/tenant resolution |
| Management | ePO, Trellix Agent, `GlobalPolicy.opg` | Policy distribution & incident collection |
