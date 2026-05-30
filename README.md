# Browser Forensic Extractor

A professional, read-only desktop forensic analysis tool designed to extract, decrypt, and audit historical user activity from local web browsers (**Google Chrome**, **Microsoft Edge**, and **Mozilla Firefox**). 

The tool performs live database acquisitions in a forensically sound manner, consolidates data into a unified chronological timeline, executes a heuristic diagnostics suite to identify suspicious user activity (e.g., cleared history or incognito sessions), and generates detailed PDF, CSV, and JSON investigation reports.

---

## Key Features

*   **Multi-Browser Profile Scanning**: Automatically detects and scans active profiles (e.g., `Default`, `Profile 1`) for Google Chrome, Microsoft Edge, and Mozilla Firefox.
*   **Forensic Soundness (Read-Only Copy Mode)**: Preserves original database metadata. The tool copies files (like `History`, `Cookies`, `Web Data`, and `Login Data`) to a local workspace temporary directory before analysis, leaving original system databases completely untouched and verifying timestamp integrity.
*   **Local State Decryption (DPAPI)**: Automatically parses Google Chrome and Microsoft Edge `Local State` JSON files, retrieves the master key, and decrypts AES-GCM encrypted cookies and saved login credentials using Windows Data Protection API (DPAPI).
*   **Forensic Heuristics & Diagnostics Engine**: Flags anomalies and suspicious activities:
    *   **Deleted History Gap Analysis**: Scans SQLite auto-increment ID gaps to calculate deleted history counts.
    *   **Cleared History Detection**: Flags profiles with extensive cookies or logins but minimal history (indicating selective history clearing).
    *   **Incognito Session Identification**: Detects "orphan" cookies created during intervals with no matching history visits, pointing to potential Private/Incognito browsing session residues.
    *   **Suspicious Download Path Auditing**: Highlights files downloaded to sensitive system directories (e.g., `System32`, `Windows`, `AppData`).
*   **Unified Timelines & Search Filters**: Consolidates history, downloads, cookies, autofill fields, and login attempts into a single chronological view with keyword, date, and category filtering.
*   **Professional PDF, CSV, and JSON Reporting**: Exports case information, investigator notes, complete timelines, and flagged findings into standardized reports.

---

## Directory Structure

```text
browser_forensics/
│
├── main.py              # Application entrypoint; initializes and runs the Tkinter GUI.
├── gui.py               # Handles the dark-themed dashboard layout, search filters, and events.
├── parsers.py           # Core extraction logic for Chrome, Edge, and Firefox SQLite databases.
├── reports.py           # Report compilation engine (PDF creation via ReportLab, JSON, CSV).
├── utils.py             # Database copying, time format conversions, and DPAPI cryptography.
├── check_env.py         # Utility to inspect environment variables and browser installation paths.
└── test_extraction.py   # CLI-based diagnostic script to run validation tests.
```

---

## Getting Started

### 1. Prerequisites
Ensure you have Python 3.10+ installed. The tool depends on standard packages as well as a few third-party libraries for PDF styling and data manipulation.

To check if your local environment is ready, run:
```powershell
python check_env.py
```

If any packages are missing, install them via pip:
```powershell
pip install pandas reportlab
```
*(Tkinter and SQLite3 are bundled with standard Python distributions on Windows).*

### 2. How to Run the Tool

#### Option A: Launch the Desktop GUI Dashboard
Launch the fully-interactive dark-themed dashboard:
```powershell
python main.py
```
*   **Scan & Extract**: Scans all active browsers and populates the tree views.
*   **Artifact Explorer**: Browse individual databases (History, Downloads, Cookies, Autofill, Logins).
*   **Unified Timeline**: Review chronological user actions.
*   **Reports & Notes**: Fill in investigator notes, analyze diagnostic flags, and export PDF/CSV/JSON reports.

#### Option B: Run validation CLI tests
Run a non-interactive acquisition test that compiles forensic statistics and saves test reports to the project root:
```powershell
python test_extraction.py
```

---

## Forensic Integrity & Data Safety
*   **Database Locking Avoided**: Creating copies of the database files prevents conflicts with active browser instances (so scans can run even when Chrome or Firefox is actively open).
*   **Read-Only Operations**: SQLite databases are opened with URI parameters set to `mode=ro` (Read-Only) to protect evidence from accidental modification.
*   **Local Processing**: No data is transmitted to external servers. All decryption, analysis, and report compiles are done entirely on the host machine.
