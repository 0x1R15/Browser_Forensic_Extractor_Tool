# Browser Forensic Extractor

A two-component forensic suite for browser activity evidence:

| Component | What it is | Acquisition model |
|---|---|---|
| **`extension/`** | WebExtension (Chrome/Edge, Manifest V3) | **Live capture** — records evidence as it happens, with a tamper-evident hash chain |
| **`desktop/`** | Python/Tkinter tool (Windows) | **Offline acquisition** — parses Chrome/Edge/Firefox SQLite profile databases with DPAPI decryption |

Both components run entirely on the examiner's machine. No network calls, no telemetry.

---

## The extension (primary component)

A browser cannot read another browser's SQLite files from a sandboxed extension — so the extension does what only an extension can do: it becomes a **witness installed inside the browser**, capturing evidence at the moment it is created and protecting it with cryptography.

### Evidence capture (background service worker)

Every observation is appended to an **append-only SHA-256 hash chain** stored in IndexedDB: each event carries `seq`, timestamp, payload, the previous event's hash, and its own hash. Retroactive modification of any event breaks its hash and every hash after it — silent tampering is detectable by re-walking the chain.

| Event | Source API | Forensic value |
|---|---|---|
| `visit` | `history.onVisited` | Navigation with URL, title, visit/typed counts |
| `incognito-visit` | `webNavigation.onCommitted` | **Private-browsing navigations** (never reach history) |
| `tab-session` | `tabs.onRemoved` | Dwell time per page — how long content was viewed |
| `download`, `download-state` | `downloads.onCreated/onChanged` | Files, sizes, sources, terminal state |
| `cookie-add`, `cookie-del` | `cookies.onChanged` | Cookie lifecycle with causes |
| `history-delete` | `history.onVisitRemoved` | **Exact record of manual history deletion**, including full wipes |
| `snapshot` | on demand | Baseline acquisition digest |
| `capture-start/stop`, `heartbeat`, `reset` | lifecycle | Chain-of-custody bookkeeping; heartbeats prove capture continuity |

### Baseline acquisition

One click bulk-captures what the browser already knows at install time — full history, all downloads, all cookies — through the `history`/`downloads`/`cookies` APIs. The snapshot is digested (SHA-256 over canonical JSON) and the digest is chained, making the snapshot contents tamper-evident as a unit.

### Diagnostics engine (ported from the desktop tool + extension-native)

| Finding | Severity | Origin |
|---|---|---|
| Evidence chain integrity failure | Critical | extension-native |
| Entire history wiped while capture active | Critical | extension-native (live capture) |
| Selective history deletion (per-event, URLs recovered) | High | ported heuristic (ID-gap analysis → live removal events) |
| Suspicious download location (System32, Temp, AppData, `.ssh`, Startup, `/tmp`, `/etc`, …) | High | ported heuristic, extended cross-platform |
| Executable downloaded / executable over plain HTTP | Medium–High | extension-native |
| Cleared-history footprint mismatch (many cookies, almost no history) | High | ported heuristic |
| Incognito activity observed | Medium | extension-native |
| Orphan cookies — set with no visit within 15 min | Medium | ported heuristic (incognito / selective-deletion residue) |

### Dashboard

Full-page investigator UI: **Overview** (stats, 30-day activity chart, top domains), **Unified Timeline** (searchable/filterable, live + baseline merged), **Artifacts** (history/downloads/cookies tables), **Findings**, **Chain of Custody** (event/hash table, one-click verification), **Reports**, **Settings** (per-category capture toggles, evidence-store reset).

### Reports & export

- **Evidence package (JSON)** — case metadata, summary, findings, full hash-chained event log, chain head, baseline artifacts
- **Unified timeline (CSV)** — same column contract as the desktop exporter
- **Case report (Print/PDF)** — print-styled report with case information, evidence summary, findings table, timeline excerpt, and signature lines; use the browser's *Save as PDF*

### Install (developer mode)

1. Chrome/Edge → `chrome://extensions`
2. Enable **Developer mode** → **Load unpacked** → select the `extension/` directory
3. Pin the icon. The popup shows capture status and chain health; **Open Dashboard** for the full UI.

> To capture incognito browsing, enable *Allow in Incognito* for the extension. The store is local to the browser profile; exporting the JSON package preserves the evidence for case files.

### Firefox

Chromium-first (MV3 service worker). A Firefox port needs `browser_specific_settings` and an event-page background; the logic in `extension/lib/` is browser-API-compatible via the `browser ?? chrome` bridge and ports unchanged.

### Permissions rationale

| Permission | Why |
|---|---|
| `history` | Baseline acquisition + live visit/deletion events |
| `downloads` | Download evidence |
| `cookies` + `<all_urls>` | Cookie inventory + change events across all sites |
| `tabs`, `webNavigation` | Incognito detection, dwell-time sessions |
| `storage`, `unlimitedStorage` | Local IndexedDB evidence store |
| `alarms` | 12-hour chain-continuity heartbeats |

No `webRequest`, no content scripts, no remote code, no network access.

---

## The desktop tool (Windows deep acquisition)

Offline parser for browser **profile databases on disk** — including activity that predates any extension install, and artifacts extensions cannot reach (saved logins, autofill).

```powershell
cd desktop
pip install -r requirements.txt
python main.py              # Tkinter dashboard
python test_extraction.py   # CLI validation run
```

- **Read-only acquisition**: `History`, `Cookies`, `Web Data`, `Login Data` (Chrome/Edge) and `places.sqlite`, `cookies.sqlite`, `formhistory.sqlite`, `logins.json` (Firefox) are copied to a workspace temp directory, then opened SQLite `mode=ro`. Originals are never touched.
- **DPAPI + AES-256-GCM decryption** of Chrome/Edge cookies and saved credentials via the `Local State` master key.
- **Heuristics**: deleted-history ID-gap analysis, cleared-history detection, incognito/orphan-cookie analysis, suspicious download paths.
- **Reports**: PDF (ReportLab, paginated with case headers), CSV, JSON.

> Requires Windows (DPAPI) and Chrome/Edge/Firefox profile paths; run under the target user's context.

---

## Forensic methodology notes

- The extension's chain proves **integrity** (evidence unchanged since capture), not **completeness** — capture only observes from install onward, and a browser restart clears memory of pending downloads. The desktop tool covers pre-install history from disk.
- Cookie **values** are not stored by default (they are bearer secrets); metadata and lifecycle events are sufficient for timeline and anomaly analysis. Can be enabled in Settings.
- Browser-side auto-pruning of old history entries also surfaces as `history-delete` events; examiners should weigh counts against browsing age.
- The evidence store resets only through an explicit, confirmed dashboard action that itself starts a fresh genesis chain.

## Repository layout

```text
├── extension/                  # MV3 web extension (live capture & analysis)
│   ├── manifest.json
│   ├── background/service-worker.js
│   ├── lib/                    # chain, db, acquisition, diagnostics, export, util
│   ├── popup/                  # status card
│   ├── dashboard/              # full-page investigator UI
│   └── icons/                  # generated assets (+ src/gen_icons.py)
└── desktop/                    # Python/Tkinter offline acquisition tool
    ├── main.py                 # GUI entrypoint
    ├── gui.py                  # dashboard UI
    ├── parsers.py              # SQLite extraction + heuristics
    ├── reports.py              # PDF/CSV/JSON reporting
    ├── utils.py                # copying, timestamps, DPAPI/AES-GCM
    └── check_env.py            # environment diagnostics
```
