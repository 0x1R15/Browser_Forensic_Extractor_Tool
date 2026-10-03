# Browser Forensic Extractor

A two-component forensic suite for browser activity evidence:

| Component | What it is | Acquisition model |
|---|---|---|
| **`extension/`** | WebExtension (Chrome/Edge, Manifest V3) | **Live capture**: records evidence as it happens, guarded by a tamper-evident hash chain |
| **`desktop/`** | Python/Tkinter tool (Windows) | **Offline acquisition**: parses Chrome/Edge/Firefox SQLite profile databases with DPAPI decryption |

Both components run entirely on the examiner's machine. No network calls, no telemetry.

---

## Using the extension: a guide for users

The extension is a silent witness installed inside the browser. It records browsing evidence as it happens and protects it with cryptography so it can be proven unaltered later. You do not need to be technical to use it: install it once, click one button, and it works in the background from then on.

### 1. Install it (one time)

1. Open Chrome or Edge and go to `chrome://extensions` (on Edge: `edge://extensions`).
2. Turn on **Developer mode** (toggle at the top right).
3. Click **Load unpacked** and select the `extension/` folder from this repository.
4. Click the puzzle-piece icon in the toolbar and pin **Forensic Browser Extractor**.

The extension is now installed. Nothing has been recorded yet; that starts in step 3 below.

### 2. The popup: your status panel

Click the FBEx icon in the toolbar. The popup shows everything at a glance:

- **Capture: active/paused** with a green dot, plus a switch to pause or resume recording
- **Chain verified** with the number of evidence events: the health check for your evidence
- Live counters: visits, private navigations, downloads, cookie events
- **Acquire Baseline** and **Open Dashboard** buttons

### 3. Your first five minutes

1. Open the popup and press **Acquire Baseline**. This snapshots everything the browser already knows (full history, all downloads, all cookies) so old activity is included too. Wait for the confirmation line.
2. Press **Open Dashboard**.
3. In the dashboard, press **Run Analysis** in the top bar, then look at the **Findings** page.

From this moment on, capture runs silently in the background, even when the dashboard is closed. Each browser restart resumes automatically.

### 4. Day-to-day use

You normally do nothing. When you want to review or export:

- **Overview**: totals for visits, downloads, deletions, chain health, plus a 30-day activity chart and top domains
- **Unified Timeline**: every recorded event in chronological order. Search by keyword, filter by type or date range
- **Artifacts**: browse the baseline snapshot as tables (history, downloads, cookies)
- **Findings**: press **Run Analysis** to re-scan, then read the flagged anomalies
- **Chain of Custody**: the raw evidence log with per-event hashes
- **Settings**: turn individual capture categories on or off (visits, private tabs, downloads, cookies, dwell time)

### 5. Reading findings

Findings are ranked by severity:

| Severity | Meaning | Typical examples |
|---|---|---|
| Critical | Evidence tampering or deliberate wiping | chain verification failed; entire history cleared while capture was active |
| High | Strong indicator of intentional concealment | individual history entries deleted; downloads saved to system folders; many cookies but almost no history |
| Medium | Suspicious but explainable | private-browsing sessions; cookies set with no matching visits; executable files downloaded |
| Info | Note for the investigator | empty evidence store before the first baseline |

Each finding lists its evidence (what was observed, when, and from where), so you can verify the conclusion yourself in the timeline.

### 6. Proving the evidence was not altered

Open **Chain of Custody** and press **Verify chain**. The tool re-computes every cryptographic link from the very first event. If anyone (or anything) modified, inserted, or deleted a stored event, verification names the exact event number where the chain breaks. A green banner means every event is byte-for-byte as it was when captured.

### 7. Getting reports out

Open **Reports**, fill in the case fields (case ID, subject, device, investigator, notes), press **Save metadata**, then:

- **Evidence package (JSON)**: the complete case file, including the full hash-chained event log and chain head. This is the archival format.
- **Unified timeline (CSV)**: one row per event for spreadsheets.
- **Case report (Print / PDF)**: opens the print dialog on a formatted case report; choose *Save as PDF* as the destination.

Export after each session if the evidence matters: files land on your disk and are safe from any later browser-side reset.

### 8. Capturing private browsing (optional)

By default the browser hides private/incognito tabs from extensions. To record them:

1. Right-click the FBEx toolbar icon and choose **Manage extension** (or find it on `chrome://extensions`).
2. Enable **Allow in Incognito**.

Private navigations are then logged as `incognito-visit` evidence events and summarized under Findings.

### 9. Your data stays yours

Everything is stored locally in this browser profile only: no accounts, no sync, no network calls. Cookie values (which are login secrets) are not stored by default. The **Settings** page has an explicit, confirmed reset that wipes the evidence store and starts a fresh chain.

---

## How the extension works (technical)

A browser cannot read another browser's SQLite files from a sandboxed extension, so the extension does what only an extension can do: it becomes a **witness installed inside the browser**, capturing evidence at the moment it is created and protecting it with cryptography.

### Evidence capture (background service worker)

Every observation is appended to an **append-only SHA-256 hash chain** stored in IndexedDB: each event carries `seq`, timestamp, payload, the previous event's hash, and its own hash. Retroactive modification of any event breaks its hash and every hash after it, so silent tampering is detectable by re-walking the chain.

| Event | Source API | Forensic value |
|---|---|---|
| `visit` | `history.onVisited` | Navigation with URL, title, visit/typed counts |
| `incognito-visit` | `webNavigation.onCommitted` | **Private-browsing navigations** (never reach history) |
| `tab-session` | `tabs.onRemoved` | Dwell time per page: how long content was viewed |
| `download`, `download-state` | `downloads.onCreated/onChanged` | Files, sizes, sources, terminal state |
| `cookie-add`, `cookie-del` | `cookies.onChanged` | Cookie lifecycle with causes |
| `history-delete` | `history.onVisitRemoved` | **Exact record of manual history deletion**, including full wipes |
| `snapshot` | on demand | Baseline acquisition digest |
| `capture-start/stop`, `heartbeat`, `reset` | lifecycle | Chain-of-custody bookkeeping; heartbeats prove capture continuity |

### Baseline acquisition

One click bulk-captures what the browser already knows at install time: full history, all downloads, all cookies, through the `history`/`downloads`/`cookies` APIs. The snapshot is digested (SHA-256 over canonical JSON) and the digest is chained, making the snapshot contents tamper-evident as a unit.

### Diagnostics engine (ported from the desktop tool + extension-native)

| Finding | Severity | Origin |
|---|---|---|
| Evidence chain integrity failure | Critical | extension-native |
| Entire history wiped while capture active | Critical | extension-native (live capture) |
| Selective history deletion (per-event, URLs recovered) | High | ported heuristic (ID-gap analysis advanced to live removal events) |
| Suspicious download location (System32, Temp, AppData, `.ssh`, Startup, `/tmp`, `/etc`, and more) | High | ported heuristic, extended cross-platform |
| Executable downloaded / executable over plain HTTP | Medium to High | extension-native |
| Cleared-history footprint mismatch (many cookies, almost no history) | High | ported heuristic |
| Incognito activity observed | Medium | extension-native |
| Orphan cookies: set with no visit within 15 min | Medium | ported heuristic (incognito / selective-deletion residue) |

### Dashboard

Full-page investigator UI: **Overview** (stats, 30-day activity chart, top domains), **Unified Timeline** (searchable and filterable, live plus baseline merged), **Artifacts** (history/downloads/cookies tables), **Findings**, **Chain of Custody** (event/hash table, one-click verification), **Reports**, **Settings** (per-category capture toggles, evidence-store reset).

### Reports and export

- **Evidence package (JSON)**: case metadata, summary, findings, full hash-chained event log, chain head, baseline artifacts
- **Unified timeline (CSV)**: same column contract as the desktop exporter
- **Case report (Print/PDF)**: print-styled report with case information, evidence summary, findings table, timeline excerpt, and signature lines; use the browser's *Save as PDF*

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

Offline parser for browser **profile databases on disk**: activity that predates any extension install, plus artifacts extensions cannot reach (saved logins, autofill).

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

Requires Windows (DPAPI) and Chrome/Edge/Firefox profile paths; run under the target user's context.

---

## Forensic methodology notes

- The extension's chain proves **integrity** (evidence unchanged since capture), not **completeness**: capture only observes from install onward, and a browser restart clears memory of pending downloads. The desktop tool covers pre-install history from disk.
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
