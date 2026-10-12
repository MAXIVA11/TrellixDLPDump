# Labels, encryption & identity, up close

Two supporting pillars: **honouring data labels / encrypting content** (so DLP understands
Microsoft Purview sensitivity labels and RMS-protected files, and can encrypt as a
reaction), and **knowing who the user is** (so policy can be identity-aware). A
**read-only static** teardown, companion to [`FCAGS.md`](FCAGS.md).

*Method: version resources + imports. Nothing run or modified.*

## Labels & rights management (MIP / Purview)

**[observed]** The Microsoft Information Protection SDK ships with the agent:

| Module | FileDescription |
|---|---|
| `mip_core.dll` | MIP SDK Core Library |
| `mip_file_sdk.dll` | MIP File SDK Library |
| `mip_protection_sdk.dll` | MIP Protection SDK Library |
| `mip_upe_sdk.dll` | MIP Policy SDK Library |
| `mip_ClientTelemetry.dll` | Microsoft Applications Telemetry SDK |
| `TitusSDKInterface.dll` | Titus/Fortra classification label interface |

**[inferred]** The agent reads and honours **Purview/MIP sensitivity labels** and can open
**RMS-protected** content for inspection, and interoperates with Titus labels — so a
"Confidential"-labelled document is recognised as such regardless of its bytes.

## Cryptography

**[observed]** `cryptographyservices.dll` (OpenText IDOL), `libcrypto-3-x64.dll` +
`fips.dll` (**OpenSSL**), and the OS `bcrypt`/`CRYPT32` imports in `fcags.exe`.
**[inferred]** Used for hashing (fingerprints), secure transport, and **encryption
reactions** (a policy can encrypt content on egress). FIPS-mode OpenSSL implies support for
FIPS-validated deployments.

## Identity (Entra / MSAL)

**[observed]** `msalruntime.dll`, `Microsoft.Identity.Client*`, `AzureAuthentication.dll`
("Trellix Azure Authentication"), `EntraIdBridge.dll`; `fcags.exe` imports
`EntraIdBridge.dll` and does AD lookups (`ACTIVEDS`, `NETAPI32`, `DNSAPI`).
**[inferred]** The agent resolves the signed-in **user and tenant** via Microsoft Entra
(Azure AD) / MSAL and on-prem Active Directory, so policy and incidents can be attributed
to an identity and scoped per user/group.

## Not established

- **[unknown]** Which label/RMS or identity operations require outbound cloud calls.
- **[unknown]** The encryption reaction's key management and algorithms.
