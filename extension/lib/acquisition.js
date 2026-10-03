// Baseline acquisition: bulk-capture the browser's existing forensic state
// through the WebExtension history / downloads / cookies APIs.
//
// This is the extension-side analogue of the desktop tool's SQLite file
// acquisition: it snapshots what the browser already knows at install time,
// so analysis covers activity that predates live capture.

import { api, nowIso, domainOf } from './util.js';
import { digestObject } from './chain.js';

function promisify(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn(...args, (result) => {
      const err = api.runtime.lastError;
      if (err) reject(new Error(err.message));
      else resolve(result);
    });
  });
}

/**
 * Acquires the full baseline. Returns a snapshot record:
 *   { id, ts, kind: 'baseline', digest, counts, artifacts }
 * The digest (SHA-256 over the canonical artifacts) is chained as evidence,
 * making the snapshot contents tamper-evident as a unit.
 */
export async function acquireBaseline() {
  const [historyItems, downloadItems, cookieItems] = await Promise.all([
    promisify(api.history.search, { text: '', startTime: 0, maxResults: 0 }),
    promisify(api.downloads.search, {}),
    promisify(api.cookies.getAll, {}),
  ]);

  const history = historyItems
    .map((h) => ({
      url: h.url,
      title: h.title || '',
      domain: domainOf(h.url),
      lastVisitTime: h.lastVisitTime ? new Date(h.lastVisitTime).toISOString() : null,
      visitCount: h.visitCount || 0,
      typedCount: h.typedCount || 0,
    }))
    .sort((a, b) => (b.lastVisitTime || '').localeCompare(a.lastVisitTime || ''));

  const downloads = downloadItems
    .map((d) => ({
      id: d.id,
      url: d.finalUrl || d.url,
      filename: d.filename || '',
      fileExt: (d.filename || '').split('.').pop()?.toLowerCase() || '',
      referrer: d.referrer || '',
      mime: d.mime || '',
      bytes: d.fileSize ?? d.bytesReceived ?? 0,
      totalBytes: d.totalBytes ?? 0,
      state: d.state,
      danger: d.danger,
      startTime: d.startTime ? new Date(d.startTime).toISOString() : null,
      paused: !!d.paused,
      exists: d.exists,
    }))
    .sort((a, b) => (b.startTime || '').localeCompare(a.startTime || ''));

  const cookies = cookieItems
    .map((c) => ({
      domain: c.domain,
      name: c.name,
      value: c.value,
      path: c.path,
      secure: !!c.secure,
      httpOnly: !!c.httpOnly,
      session: !!c.session,
      sameSite: c.sameSite || '',
      expirationDate: c.expirationDate || null,
      expiryIso: c.expirationDate ? new Date(c.expirationDate * 1000).toISOString() : null,
      hostOnly: !!c.hostOnly,
    }))
    .sort((a, b) => `${a.domain}|${a.name}`.localeCompare(`${b.domain}|${b.name}`));

  const ts = nowIso();
  const artifacts = { history, downloads, cookies };
  const digest = await digestObject(artifacts);

  return {
    id: ts,
    ts,
    kind: 'baseline',
    digest,
    counts: { history: history.length, downloads: downloads.length, cookies: cookies.length },
    artifacts,
  };
}
