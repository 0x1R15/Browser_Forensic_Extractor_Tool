// Shared utilities: API bridge, time handling, canonical serialization, CSV, formatting.

/**
 * WebExtension API bridge. Prefers the promise-based `browser` namespace
 * (Firefox / emerging standard) and falls back to `chrome` (Chromium).
 * All Chromium APIs used here return promises on MV3.
 */
export const api = globalThis.browser ?? globalThis.chrome;

export const TOOL = Object.freeze({
  name: 'Forensic Browser Extractor',
  shortName: 'FBEx',
  version: '1.0.0',
});

/** Current UTC time, ISO-8601 with millisecond precision. */
export function nowIso() {
  return new Date().toISOString();
}

/** Chrome cookie `expirationDate` (seconds since epoch) -> ISO string or null (session cookie). */
export function cookieExpiryToIso(seconds) {
  if (!seconds) return null;
  return new Date(seconds * 1000).toISOString();
}

/**
 * Normalizes any timestamp-ish value to a comparable ISO string.
 * Understands ISO strings, ms-since-epoch numbers and seconds-since-epoch
 * (heuristically: values below 1e11 are treated as seconds).
 */
export function toIso(value) {
  if (value == null) return null;
  if (typeof value === 'number') {
    const ms = value < 1e11 ? value * 1000 : value;
    return new Date(ms).toISOString();
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Safe hostname extraction; returns null for malformed / opaque URLs. */
export function domainOf(url) {
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

/**
 * Canonical JSON serialization (sorted object keys, recursive) so that
 * identical logical payloads always produce an identical byte sequence —
 * a prerequisite for stable hashing.
 */
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

/** RFC 4180-safe CSV cell quoting. */
export function csvCell(value) {
  const s = value == null ? '' : String(value);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/** Builds a CSV document from row objects and an explicit column list. */
export function toCsv(rows, columns) {
  const lines = [columns.map((c) => csvCell(c.label)).join(',')];
  for (const row of rows) {
    lines.push(columns.map((c) => csvCell(c.get(row))).join(','));
  }
  return lines.join('\r\n');
}

/** Human-readable byte size. */
export function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Local-time short timestamp for UI rendering. */
export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/** Truncated middle of long strings for table cells. */
export function midTruncate(s, max = 72) {
  if (!s) return '';
  if (s.length <= max) return s;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return s.slice(0, head) + '…' + s.slice(s.length - tail);
}

/** Extensions that mark a downloaded file as executable / high-risk. */
export const RISKY_EXTENSIONS = Object.freeze(new Set([
  'exe', 'dll', 'scr', 'msi', 'msp', 'bat', 'cmd', 'com', 'ps1', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'hta', 'jar', 'apk', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'sh', 'bash', 'py', 'pl',
]));

/** File extension of a path or filename (lowercased, no dot). */
export function fileExt(name) {
  if (!name) return '';
  const m = /\.([a-z0-9]{1,8})$/i.exec(name);
  return m ? m[1].toLowerCase() : '';
}

/**
 * Directories a download should never land in. Cross-platform port of the
 * desktop tool's Windows-focused suspicious-path list.
 */
export const SUSPICIOUS_PATH_PATTERNS = Object.freeze([
  { re: /(?:^|[\\/])windows[\\/]system32/i, label: 'Windows System32' },
  { re: /(?:^|[\\/])windows(?:[\\/]|$)/i, label: 'Windows directory' },
  { re: /appdata[\\/]local[\\/]temp/i, label: 'user Temp directory' },
  { re: /appdata[\\/]roaming/i, label: 'AppData Roaming' },
  { re: /(?:^|[\\/])\.ssh(?:[\\/]|$)/i, label: '.ssh directory' },
  { re: /startup[\\/](?:programs|menu)/i, label: 'Startup folder' },
  { re: /(?:^|[\\/])etc(?:[\\/]|$)/i, label: '/etc' },
  { re: /(?:^|[\\/])var[\\/]tmp(?:[\\/]|$)/i, label: '/var/tmp' },
  { re: /(?:^|[\\/])private[\\/]var[\\/]tmp(?:[\\/]|$)/i, label: 'macOS temp' },
]);

/** Returns the matching suspicious-path label or null. */
export function suspiciousPathLabel(path) {
  if (!path) return null;
  for (const { re, label } of SUSPICIOUS_PATH_PATTERNS) {
    if (re.test(path)) return label;
  }
  return null;
}

/** Severity ranking helper (higher = more severe). */
export const SEVERITY_ORDER = Object.freeze({ Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 });
