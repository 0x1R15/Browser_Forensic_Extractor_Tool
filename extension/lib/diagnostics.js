// Forensic diagnostics engine: the extension-side port of the desktop
// tool's heuristic suite (`run_diagnostics` in desktop/parsers.py), extended
// with signals only a live extension can observe.
//
// Ported heuristics (desktop -> extension):
//   H2 Deleted History (ID gaps)      -> live history.onVisitRemoved capture
//   H3 Cleared History footprint      -> baseline history vs cookie counts
//   H4 Incognito / orphan cookies     -> live cookie events w/o nearby visits
//   H1 Suspicious download paths      -> cross-platform path patterns
// New extension-native signals:
//   Chain integrity, explicit full-history wipe, observed incognito
//   navigation, executable/insecure-origin downloads.

import { toIso, domainOf, fileExt, RISKY_EXTENSIONS, suspiciousPathLabel, SEVERITY_ORDER } from './util.js';
import { verifyChain } from './chain.js';
import { getEvents, latestSnapshot } from './db.js';

/** Minutes around a visit in which a cookie creation is considered "explained". */
const ORPHAN_COOKIE_WINDOW_SEC = 15 * 60;
/** Orphan-cookie threshold above which a finding is raised (matches desktop). */
const ORPHAN_COOKIE_THRESHOLD = 15;
/** Cleared-history footprint thresholds (desktop: history<10 && cookies>10). */
const FOOTPRINT_MIN_HISTORY = 10;
const FOOTPRINT_MIN_COOKIES = 10;

function finding(severity, category, message, evidence, count = null) {
  return { severity, category, message, evidence, count };
}

/**
 * Runs the full diagnostic suite over the evidence store.
 * @returns {Promise<{generatedAt: string, findings: Array, summary: Object}>}
 */
export async function runDiagnostics() {
  const findings = [];
  const [events, snapshot] = await Promise.all([getEvents(), latestSnapshot()]);

  // --- 0. Evidence chain integrity -------------------------------------
  const chain = await verifyChain(events);
  if (!chain.ok) {
    findings.push(finding(
      'Critical', 'Evidence Chain Integrity',
      `Evidence log verification FAILED at event #${chain.firstBreak}. The chain has been altered, truncated, or corrupted after the fact. All downstream evidence is questionable.`,
      `First broken link: seq ${chain.firstBreak}; events stored: ${chain.length}`
    ));
  }

  // --- 1. History deletion events (live-captured, exact) ---------------
  const deletions = events.filter((e) => e.type === 'history-delete');
  if (deletions.length) {
    const fullWipe = deletions.find((e) => e.data.allHistory);
    const selective = deletions.filter((e) => !e.data.allHistory);
    if (fullWipe) {
      findings.push(finding(
        'Critical', 'History Wiped',
        `Entire browsing history was cleared on ${fullWipe.ts} while capture was active. This event was recorded live and cannot be explained by normal browsing.`,
        `Captured deletion event seq #${fullWipe.seq} (${fullWipe.ts})`
      ));
    }
    for (const del of selective) {
      const n = (del.data.urls || []).length;
      findings.push(finding(
        'High', 'Selective History Deletion',
        `${n} history ${n === 1 ? 'entry was' : 'entries were'} manually removed from browser history on ${del.ts}${n ? ` (first: ${del.data.urls[0]})` : ''}.`,
        `Deletion event seq #${del.seq}; ${n} URL(s) recovered from the removal callback`,
        n
      ));
    }
  }

  // --- 2. Observed incognito navigation --------------------------------
  const incognitoVisits = events.filter((e) => e.type === 'incognito-visit');
  if (incognitoVisits.length) {
    const domains = [...new Set(incognitoVisits.map((e) => e.data.domain).filter(Boolean))];
    findings.push(finding(
      'Medium', 'Incognito Activity',
      `${incognitoVisits.length} private/incognito ${incognitoVisits.length === 1 ? 'navigation was' : 'navigations were'} observed${domains.length ? ` to ${domains.length} distinct ${domains.length === 1 ? 'domain' : 'domains'} (e.g. ${domains.slice(0, 3).join(', ')})` : ''}.`,
      `Observed live via navigation events; private browsing leaves no history entries`,
      incognitoVisits.length
    ));
  }

  // --- 3. Orphan cookies (incognito residue / selective deletion) ------
  // Ported heuristic: cookies created when no history visit exists nearby.
  // Live cookie events carry capture timestamps, unlike the raw cookie DB.
  const visitTs = events
    .filter((e) => e.type === 'visit')
    .map((e) => Date.parse(e.ts))
    .filter((t) => !Number.isNaN(t))
    .sort((a, b) => a - b);
  const cookieAdds = events.filter((e) => e.type === 'cookie-add' && !e.data.cookie?.session);

  if (visitTs.length && cookieAdds.length) {
    const orphans = cookieAdds.filter((c) => {
      const t = Date.parse(c.ts);
      // Binary-search the closest visit timestamp.
      let lo = 0, hi = visitTs.length - 1, best = Infinity;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const d = Math.abs(visitTs[mid] - t);
        if (d < best) best = d;
        if (visitTs[mid] < t) lo = mid + 1; else hi = mid - 1;
      }
      return best > ORPHAN_COOKIE_WINDOW_SEC * 1000;
    });
    if (orphans.length > ORPHAN_COOKIE_THRESHOLD) {
      const domains = [...new Set(orphans.map((c) => c.data.cookie?.domain).filter(Boolean))];
      findings.push(finding(
        'Medium', 'Incognito / Deleted Activity Residue',
        `${orphans.length} cookies were set with no matching recorded visit within 15 minutes. This pattern suggests private-browsing sessions or selective history deletion (first observed: ${orphans[0].ts}).`,
        `Orphan cookies: ${orphans.length} of ${cookieAdds.length}; sample domains: ${domains.slice(0, 3).join(', ') || 'n/a'}`,
        orphans.length
      ));
    }
  }

  // --- 4. Downloads: suspicious locations & risky payloads -------------
  // Evidence sources: live download events + latest baseline snapshot.
  const liveDownloads = events
    .filter((e) => e.type === 'download')
    .map((e) => ({ ts: e.ts, ...e.data }));
  const baselineDownloads = (snapshot?.artifacts?.downloads || []).map((d) => ({
    ts: d.startTime, url: d.url, filename: d.filename, bytes: d.bytes, state: d.state,
  }));
  const allDownloads = [...liveDownloads, ...baselineDownloads];
  const seenPathKeys = new Set();

  for (const dl of allDownloads) {
    const label = suspiciousPathLabel(dl.filename || '');
    if (label && !seenPathKeys.has(dl.filename)) {
      seenPathKeys.add(dl.filename);
      findings.push(finding(
        'High', 'Suspicious Download Location',
        `File "${(dl.filename || '').split(/[\\/]/).pop()}" was downloaded to a highly unusual location (${label}): ${dl.filename}.`,
        `Path: ${dl.filename}; Source: ${dl.url || 'unknown'}; Time: ${dl.ts || 'unknown'}`
      ));
    }
  }

  for (const dl of liveDownloads) {
    const ext = fileExt(dl.filename || '');
    if (ext && RISKY_EXTENSIONS.has(ext)) {
      const insecure = /^http:\/\//i.test(dl.url || '');
      findings.push(finding(
        insecure ? 'High' : 'Medium',
        insecure ? 'Executable from Insecure Origin' : 'Executable Downloaded',
        `An executable file (.${ext}) was downloaded${insecure ? ' over an insecure HTTP connection' : ''}: "${(dl.filename || '').split(/[\\/]/).pop()}".`,
        `File: ${dl.filename}; Source: ${dl.url || 'unknown'}; Time: ${dl.ts}`,
      ));
    }
  }

  // --- 5. Cleared-history footprint mismatch (ported) -------------------
  if (snapshot) {
    const histCount = snapshot.counts.history;
    const cookieCount = snapshot.counts.cookies;
    const liveVisits = events.filter((e) => e.type === 'visit').length;
    if (histCount < FOOTPRINT_MIN_HISTORY && cookieCount > FOOTPRINT_MIN_COOKIES && liveVisits < FOOTPRINT_MIN_HISTORY) {
      findings.push(finding(
        'High', 'Potential Cleared History',
        `Browser shows an active footprint (${cookieCount} cookies) but almost no browse history (${histCount} baseline URLs, ${liveVisits} captured visits). This strongly implies history was cleared before or shortly after acquisition.`,
        `Baseline history URLs: ${histCount}; cookies: ${cookieCount}; live visits: ${liveVisits}`
      ));
    }
  } else if (!events.length) {
    findings.push(finding(
      'Info', 'No Evidence Acquired',
      'No baseline acquisition has been run and no live events are captured yet. Run "Acquire Baseline" and enable live capture to build an evidence set.',
      'Evidence store is empty'
    ));
  }

  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) summary[f.severity] += 1;
  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  return {
    generatedAt: new Date().toISOString(),
    chain: { ok: chain.ok, head: chain.head, length: chain.length },
    findings,
    summary,
  };
}
