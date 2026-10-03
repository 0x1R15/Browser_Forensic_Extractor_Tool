// Evidence package assembly and export: unified timeline, JSON package, CSV.

import { TOOL, toIso, domainOf, toCsv, midTruncate } from './util.js';
import { getEvents, allSnapshots, getMeta, setMeta, countEvents } from './db.js';
import { runDiagnostics } from './diagnostics.js';

const DEFAULT_CASE = {
  caseId: 'INV-2026-001',
  suspectName: '',
  deviceName: '',
  investigator: '',
  notes: '',
};

/** Loads (or defaults) case metadata persisted by the dashboard. */
export async function getCaseMeta() {
  return { ...DEFAULT_CASE, ...((await getMeta('case', {})) || {}) };
}

/** Persists case metadata from the dashboard form. */
export async function saveCaseMeta(meta) {
  const clean = { ...DEFAULT_CASE, ...meta };
  await setMeta('case', clean);
  return clean;
}


/**
 * Builds the unified chronological timeline from live events plus the latest
 * baseline snapshot artifacts (mirrors the desktop tool's consolidated view).
 * Each row: {ts, type, domain, detail, source, seq, hash}
 */
export async function buildTimeline() {
  const rows = [];
  const events = await getEvents();

  for (const e of events) {
    rows.push({
      ts: e.ts,
      type: e.type,
      domain: eventDomain(e),
      detail: eventDetail(e),
      source: 'live capture',
      seq: e.seq,
      hash: e.hash,
    });
  }

  const snaps = await allSnapshots();
  const latest = snaps.length ? snaps[snaps.length - 1] : null;
  if (latest) {
    for (const h of latest.artifacts.history) {
      rows.push({
        ts: h.lastVisitTime, type: 'history', domain: h.domain,
        detail: h.title || h.url, source: 'baseline', seq: null, hash: null,
      });
    }
    for (const d of latest.artifacts.downloads) {
      rows.push({
        ts: d.startTime, type: 'download', domain: domainOf(d.url),
        detail: d.filename || d.url, source: 'baseline', seq: null, hash: null,
      });
    }
    for (const c of latest.artifacts.cookies) {
      rows.push({
        ts: latest.ts, type: 'cookie-inventory', domain: c.domain,
        detail: `${c.name}=${midTruncate(c.value, 24)}`, source: 'baseline', seq: null, hash: null,
      });
    }
  }

  rows.sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));
  return rows;
}

function eventDomain(e) {
  const d = e.data.domain ?? e.data.cookie?.domain ?? domainOf(e.data.url ?? '');
  return d || '';
}

function eventDetail(e) {
  switch (e.type) {
    case 'visit':
      return `${e.data.title ? e.data.title + ' — ' : ''}${e.data.url}`;
    case 'incognito-visit':
      return `[private] ${e.data.url} (${e.data.transition || ''})`;
    case 'tab-session':
      return `${e.data.url || ''} — dwell ${e.data.dwellSec}s${e.data.incognito ? ' [private]' : ''}`;
    case 'download':
      return `${e.data.filename || e.data.url} (${e.data.bytes || 0} bytes)`;
    case 'download-state':
      return `download #${e.data.id} → ${e.data.state}${e.data.error ? ` (${e.data.error})` : ''}`;
    case 'cookie-add':
    case 'cookie-del': {
      const c = e.data.cookie || {};
      return `${c.domain || ''} ${c.name || ''} path=${c.path || '/'}${e.data.cookie?.cause ? ` cause=${e.data.cookie.cause}` : ''}`;
    }
    case 'history-delete':
      return e.data.allHistory
        ? 'ENTIRE history cleared'
        : `${e.data.count} URL(s) removed${e.data.urls?.length ? ` — e.g. ${e.data.urls[0]}` : ''}`;
    case 'snapshot':
      return `baseline acquired: ${e.data.counts.history} URLs, ${e.data.counts.downloads} downloads, ${e.data.counts.cookies} cookies (digest ${e.data.digest.slice(0, 12)}…)`;
    case 'capture-start':
      return `live capture started${e.data.reason ? ` (${e.data.reason})` : ''}`;
    case 'capture-stop':
      return 'live capture stopped';
    case 'heartbeat':
      return 'capture continuity heartbeat';
    case 'reset':
      return `evidence log reset${e.data.reason ? ` (${e.data.reason})` : ''}`;
    default:
      return JSON.stringify(e.data).slice(0, 120);
  }
}

/** Full evidence package for JSON export: case + chain + findings + events + snapshots. */
export async function buildEvidencePackage() {
  const [events, snaps, caseMeta, diag, count] = await Promise.all([
    getEvents(), allSnapshots(), getCaseMeta(), runDiagnostics(), countEvents(),
  ]);

  const counts = {};
  for (const e of events) counts[e.type] = (counts[e.type] || 0) + 1;

  return {
    tool: { name: TOOL.name, version: TOOL.version },
    generatedAt: new Date().toISOString(),
    case: caseMeta,
    summary: {
      eventCount: count,
      eventsByType: counts,
      snapshots: snaps.length,
      baselineCounts: snaps.length ? snaps[snaps.length - 1].counts : null,
      findings: diag.summary,
    },
    chain: diag.chain,
    findings: diag.findings,
    events,
    snapshots: snaps.map((s) => ({ id: s.id, ts: s.ts, digest: s.digest, counts: s.counts })),
    baselineArtifacts: snaps.length ? snaps[snaps.length - 1].artifacts : null,
  };
}

/** Unified-timeline CSV (column contract mirrors the desktop CSV exporter). */
export async function buildTimelineCsv() {
  const rows = await buildTimeline();
  return toCsv(rows, [
    { label: 'Timestamp', get: (r) => r.ts || '' },
    { label: 'Event Type', get: (r) => r.type },
    { label: 'Domain', get: (r) => r.domain },
    { label: 'Primary Info', get: (r) => (r.seq != null ? `#${r.seq}` : r.source) },
    { label: 'Detail', get: (r) => r.detail },
    { label: 'Source', get: (r) => r.source },
    { label: 'Evidence Hash', get: (r) => r.hash || '' },
  ]);
}

/** Triggers a browser download of a generated text artifact. */
export function downloadText(filename, mime, text) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
