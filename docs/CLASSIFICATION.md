# Content classification, up close

Classification is how Trellix DLP turns bytes into a decision: *does this content match a
rule?* It has two halves — **extraction** (make any file into text) and **matching**
(test that text against the policy). This is a **read-only static** teardown, companion to
[`FCAGS.md`](FCAGS.md).

*Method: file inventory, version resources, and the `CSF::…` symbols/strings and
build-tree paths embedded in `fcags.exe`. Nothing run or modified.*

## Extraction — KeyView + OCR

**[observed]**
- ~194 **KeyView** filter modules (`*sr.dll`, `kp*rdr.dll`, `kv*.dll`) — OpenText KeyView,
  version **25.3.0.0** (`formats.ini`), the same engine used by e-discovery products. It
  cracks open **~400 file formats** — Office, PDF, archives (zip/rar/7z/tar), mail stores
  (PST `pstsr.dll`, NSF `nsfsr.dll`), CAD, images, and more.
- `ocr.dll` (12 MB, **OpenText IDOL OCR**) — extracts text from images so a secret inside
  a screenshot or scan is still caught.
- `fcagte.exe` — the **Text Extractor** host that runs this pipeline out-of-process (so a
  malformed file crashes a worker, not the service).
- `langdetectext.dll`, `icu*` — language detection and Unicode handling.

**[inferred]** Any file bound for a monitored channel is reduced to text (plus OCR for
images) before matching, which is why the product ships hundreds of format parsers.

## Matching — the CSF classification engine

**[observed]** The "Common Scanning Framework" (`CSF::…`, under
`OPG\McAfeeCommon\ClassificationEngine` in the build tree) provides four matcher types:

| Matcher | Evidence | What it finds |
|---|---|---|
| **Dictionaries** | `Dictionary`, `DictionaryLetterNode` | keyword/phrase lists (a trie / Aho-Corasick matcher) |
| **Regular expressions** | `CSF::RegExSearcher`, `addRe2`, `RegExSearcherCache` | patterns via Google **RE2**, with proximity scoring (`getProximities`) |
| **Exact Data Matching (EDM)** | `ExactDataFingerprintsService`, `ExactDataFingerprintsSearcher::loadFingerprints`, `determineEDMVersion` | specific records (e.g. a customer database) by fingerprint |
| **Registered Documents** | `RegisterDocumentsService`, `FileHash`/`DbSignature` maps | known sensitive files by document fingerprint |

## Shared-memory tables

**[observed]** The engine's data lives in named **boost::interprocess** shared-memory
segments — `CSFClassification`, `ExactDataFingerprints`, `ExactDataMatchings`,
`EnhancedExactDataMatchings`, `RegisteredDocuments`, `Dictionaries` — registered under
`HKLM\SOFTWARE\McAfee\DLP\Agent\SharedMemory`. **[inferred]** The service builds these
once and other components map them read-only, so every process classifies against the
same tables without duplicating them.

## The flow

**[inferred]** extract text (KeyView/OCR) → run the enabled matchers (dictionary / RE2 /
EDM / registered-docs) → the `DataProtectionEngine`/`ProtectionRuleEngine` turn matches +
context (app, destination, user) into a reaction. Extraction is **observed** as a
capability; the precise ordering inside the service is not visible statically.

## Not established

- **[unknown]** The EDM fingerprint package format and the registered-documents DB format.
- **[unknown]** Scoring/threshold logic that converts matches into a rule hit.
