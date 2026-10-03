// PPTNEETPGHUB — private file gateway (Cloudflare Worker + R2)
//
//   GET    /api/file?key=...      members + admin: stream a private file
//   PUT    /api/upload?subject=&name=   admin only: upload a file, returns { key }
//   DELETE /api/file?key=...      admin only: delete a file
//   POST   /api/notify-payment    signed-in student: tell the admin on Telegram about a new payment
//
// Every call needs:  Authorization: Bearer <Firebase ID token>
// Members are verified by asking Firestore with the member's own token, so
// your Firestore security rules stay the single source of truth.

const JWK_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const MAX_UPLOAD_BYTES = 90 * 1024 * 1024; // 90 MB
const MIME = {
  pdf: 'application/pdf',
  apkg: 'application/octet-stream',
  zip: 'application/zip',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp'
};

// Internal data kept in the same bucket. Only the admin can read these.
const RESERVED_PREFIXES = ['backups/', 'system/', 'tg-invites/', 'announce-queue/'];

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

// ---------- Firebase ID token verification ----------
let jwkCache = { keys: null, exp: 0 };

async function getSigningKeys() {
  if (jwkCache.keys && Date.now() < jwkCache.exp) return jwkCache.keys;
  const res = await fetch(JWK_URL);
  if (!res.ok) throw new HttpError(503, 'Could not load signing keys');
  const data = await res.json();
  const m = /max-age=(\d+)/.exec(res.headers.get('cache-control') || '');
  jwkCache = { keys: data.keys, exp: Date.now() + (m ? Number(m[1]) * 1000 : 3600 * 1000) };
  return data.keys;
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyIdToken(token, env) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new HttpError(401, 'Invalid token');
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  } catch (e) {
    throw new HttpError(401, 'Invalid token');
  }
  if (header.alg !== 'RS256' || !header.kid) throw new HttpError(401, 'Invalid token');

  const keys = await getSigningKeys();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new HttpError(401, 'Unknown signing key');

  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );
  if (!valid) throw new HttpError(401, 'Bad token signature');

  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== env.PROJECT_ID) throw new HttpError(401, 'Wrong project');
  if (payload.iss !== 'https://securetoken.google.com/' + env.PROJECT_ID) throw new HttpError(401, 'Wrong issuer');
  if (!payload.exp || payload.exp < now) throw new HttpError(401, 'Session expired. Sign in again.');
  if (payload.iat && payload.iat > now + 300) throw new HttpError(401, 'Invalid token time');
  if (!payload.sub) throw new HttpError(401, 'Invalid token');
  if (!payload.email || payload.email_verified !== true) throw new HttpError(403, 'Verified email required');
  return payload;
}

async function requireUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) throw new HttpError(401, 'Sign in required');
  const token = m[1];
  const payload = await verifyIdToken(token, env);
  const email = payload.email.toLowerCase();
  return { token, email, isAdmin: email === env.ADMIN_EMAIL.toLowerCase() };
}

// ---------- Membership (asks Firestore using the member's own token) ----------
const memberCache = new Map(); // email -> time until which "active" is trusted (positive results only)
const deviceCache = new Map(); // email|device -> time until which "registered" is trusted

const fsDoc = (env, path, user) => fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID +
  '/databases/(default)/documents/' + path, { headers: { Authorization: 'Bearer ' + user.token } });

// 'active' | 'expired' | 'none'. A member with no end date never expires.
async function memberStatus(user, env) {
  const hit = memberCache.get(user.email);
  if (hit && hit > Date.now()) return 'active';
  const res = await fsDoc(env, 'members/' + encodeURIComponent(user.email), user);
  if (res.status !== 200) return 'none';
  const f = ((await res.json()).fields) || {};
  const end = f.expiresAt && f.expiresAt.timestampValue ? Date.parse(f.expiresAt.timestampValue) : 0;
  if (end && end <= Date.now()) return 'expired';
  memberCache.set(user.email, Date.now() + 60 * 1000); // changes take effect within a minute
  return 'active';
}

// Each member may use a limited number of registered devices. The site registers a device on sign-in.
async function deviceAllowed(user, deviceId, env) {
  if (!/^[A-Za-z0-9-]{16,64}$/.test(deviceId || '')) return false;
  const key = user.email + '|' + deviceId;
  const hit = deviceCache.get(key);
  if (hit && hit > Date.now()) return true;
  const res = await fsDoc(env, 'devices/' + encodeURIComponent(user.email), user);
  if (res.status !== 200) return false;
  const f = ((await res.json()).fields) || {};
  const list = (f.list && f.list.arrayValue && f.list.arrayValue.values) || [];
  const ok = list.some(v => v.mapValue && v.mapValue.fields && v.mapValue.fields.id && v.mapValue.fields.id.stringValue === deviceId);
  if (ok) deviceCache.set(key, Date.now() + 60 * 1000);
  return ok;
}

// ---------- Helpers ----------
function cleanKey(raw) {
  const key = (raw || '').trim();
  if (!/^[a-z0-9][a-z0-9/_.-]{2,200}$/.test(key) || key.includes('..') || key.includes('//')) {
    throw new HttpError(400, 'Invalid file key');
  }
  return key;
}

function slug(s, fallback) {
  const out = String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return out || fallback;
}

function randomId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(5)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- Routes ----------
async function handleGet(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) {
    const st = await memberStatus(user, env);
    if (st === 'expired') throw new HttpError(403, 'Your membership has ended. Renew to continue.', 'expired');
    if (st !== 'active') throw new HttpError(403, 'Premium members only', 'members');
    if (!(await deviceAllowed(user, request.headers.get('X-Device-Id'), env))) throw new HttpError(403, 'This device is not registered for your account.', 'device');
  }

  const key = cleanKey(url.searchParams.get('key'));
  if (!user.isAdmin && (RESERVED_PREFIXES.some(p => key.indexOf(p) === 0) || !MIME[key.split('.').pop()])) throw new HttpError(404, 'File not found');
  const obj = await env.FILES.get(key);
  if (!obj) throw new HttpError(404, 'File not found');

  const headers = new Headers();
  if (typeof obj.writeHttpMetadata === 'function') obj.writeHttpMetadata(headers);
  const ext = key.split('.').pop();
  if (!headers.get('Content-Type')) headers.set('Content-Type', MIME[ext] || 'application/octet-stream');
  headers.set('Cache-Control', 'private, no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Content-Security-Policy', 'sandbox');
  headers.set('Content-Disposition', 'attachment');
  return new Response(obj.body, { headers });
}

async function handleUpload(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');

  const name = url.searchParams.get('name') || '';
  const dot = name.lastIndexOf('.');
  const ext = dot > -1 ? name.slice(dot + 1).toLowerCase() : '';
  if (!MIME[ext]) throw new HttpError(400, 'Allowed files: ' + Object.keys(MIME).join(', '));

  const size = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (!size) throw new HttpError(411, 'Empty or unknown file size');
  if (size > MAX_UPLOAD_BYTES) throw new HttpError(413, 'File is larger than 90 MB');
  if (!request.body) throw new HttpError(400, 'No file received');

  const folder = slug(url.searchParams.get('subject'), 'misc');
  const base = slug(name.slice(0, dot > -1 ? dot : name.length), 'file');
  const key = folder + '/' + base + '-' + randomId() + '.' + ext;

  await env.FILES.put(key, request.body, { httpMetadata: { contentType: MIME[ext] } });
  return json({ key });
}

// ---------- Telegram alert for a new payment ----------
// Needs two secrets in Cloudflare: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID. Without them the site works as before.
const notifiedUtr = new Map();   // utr -> time, so one payment alerts once
const lastNotify = new Map();    // email -> time, so nobody can flood the admin

function trimMap(m, max) { if (m.size > max) { const first = m.keys().next().value; m.delete(first); } }

async function handleNotify(request, env, url) {
  const user = await requireUser(request, env);
  let body = null;
  try { body = await request.json(); } catch (e) { throw new HttpError(400, 'Bad request'); }
  const utr = String((body && body.utr) || '');
  if (!/^[0-9]{12}$/.test(utr)) throw new HttpError(400, 'Invalid UTR');
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return json({ ok: false, reason: 'not configured' });
  if (notifiedUtr.has(utr)) return json({ ok: true, duplicate: true });
  const last = lastNotify.get(user.email);
  if (last && Date.now() - last < 15000) throw new HttpError(429, 'Please wait a moment');

  // Read the payment with the student's own token: Firestore rules only let them read their own
  const res = await fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID +
    '/databases/(default)/documents/payments/' + utr, { headers: { Authorization: 'Bearer ' + user.token } });
  if (res.status !== 200) throw new HttpError(404, 'Payment not found');
  const f = (await res.json()).fields || {};
  const val = (k) => { const v = f[k]; return v ? (v.stringValue !== undefined ? v.stringValue : v.integerValue !== undefined ? v.integerValue : v.doubleValue !== undefined ? v.doubleValue : '') : ''; };
  if (String(val('email')).toLowerCase() !== user.email || String(val('status')) !== 'pending') throw new HttpError(403, 'Not allowed');

  const text = 'New payment to check\n\n' +
    'Amount: Rs ' + val('amount') + '\n' +
    'UTR: ' + utr + '\n' +
    'Name: ' + (val('name') || '-') + '\n' +
    'Email: ' + user.email + '\n\n' +
    'Match the UTR in your UPI app, then approve it in the admin panel.';
  notifiedUtr.set(utr, Date.now()); trimMap(notifiedUtr, 500);
  lastNotify.set(user.email, Date.now()); trimMap(lastNotify, 500);
  const tg = await fetch('https://api.telegram.org/bot' + env.TELEGRAM_BOT_TOKEN + '/sendMessage', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true,
      reply_markup: { inline_keyboard: [[{ text: 'Open admin panel', url: url.origin + '/admin.html' }]] }
    })
  });
  if (!tg.ok) { notifiedUtr.delete(utr); console.error('Telegram alert failed', tg.status); throw new HttpError(502, 'Could not send the alert'); }
  return json({ ok: true });
}

async function handleDelete(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');
  const key = cleanKey(url.searchParams.get('key'));
  await env.FILES.delete(key);
  return json({ deleted: key });
}


// ---------- Public news and counselling pages ----------
// Rendered here on the server, so search engines get real HTML. The content comes from the
// "news" collection in Firestore (anyone may read published items, only the admin may write).
const NEWS_CATEGORIES = ['Government', 'NBEMS', 'INICET', 'Seat matrix', 'Exam notice', 'Other'];
const COUNSELLING_CATEGORIES = ['Central (MCC)', 'State counselling', 'Seat matrix', 'Dates and rounds', 'Documents', 'Other'];
const LEGACY_COUNSELLING_CATS = ['MCC', 'State counselling', 'Seat matrix'];   // items saved before the Counselling section existed
const TIP_CATEGORIES = ['Study plan', 'Revision', 'Mock tests and PYQs', 'Subject tips', 'Exam day', 'Motivation'];
const FRESH_SECONDS = 120;

function h(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
// ---------- Coming soon mode ----------
// COMING_SOON = "1" (in wrangler.toml) hides the home page and every page except News and Counselling.
// Nothing is deleted. Set it to "0" to show the whole website again.
const isOn = (v) => /^(1|true|on|yes)$/i.test(String(v || '').trim());
function siteOf(env, url) {
  const s = new String(String(env.SITE_URL || url.origin).replace(/\/$/, ''));
  s.soon = isOn(env.COMING_SOON);
  return s;
}
const PREVIEW_COOKIE = 'ppt_preview';
async function previewHash(key) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(key) + '|ppt-preview'));
  return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function sameText(a, b) { a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; }
// Visiting /?preview=YOUR_KEY lets you (only) see the real website while Coming soon is on. /?preview=off ends it.
async function previewParam(env, url) {
  if (!url.searchParams.has('preview')) return null;
  const v = url.searchParams.get('preview') || '';
  const headers = new Headers({ Location: url.origin + '/', 'Cache-Control': 'no-store' });
  if (v === 'off') headers.append('Set-Cookie', PREVIEW_COOKIE + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
  else if (env.PREVIEW_KEY && String(env.PREVIEW_KEY).length >= 6 && sameText(v, env.PREVIEW_KEY)) headers.append('Set-Cookie', PREVIEW_COOKIE + '=' + await previewHash(env.PREVIEW_KEY) + '; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Lax');
  return new Response(null, { status: 302, headers });
}
async function hasPreview(request, env) {
  if (!env.PREVIEW_KEY || String(env.PREVIEW_KEY).length < 6) return false;
  const m = new RegExp('(?:^|;\\s*)' + PREVIEW_COOKIE + '=([a-f0-9]{64})').exec(request.headers.get('Cookie') || '');
  return !!m && sameText(m[1], await previewHash(env.PREVIEW_KEY));
}
function soonPage(env, url) {
  const site = String(siteOf(env, url));
  const css = '*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Poppins,system-ui,sans-serif;color:#fff;background:radial-gradient(800px 460px at 88% -5%,rgba(212,175,85,.22),transparent 62%),radial-gradient(700px 520px at -5% 105%,rgba(15,143,131,.30),transparent 60%),#0A1830;display:flex;align-items:center;justify-content:center;padding:28px 20px}' +
    '.box{max-width:520px;width:100%;text-align:center}.lg{display:block;margin:0 auto;width:150px;height:150px;border-radius:50%;box-shadow:0 0 0 2px rgba(212,175,85,.6),0 14px 40px rgba(0,0,0,.4)}' +
    '.tag{display:inline-block;margin:22px 0 10px;background:#D4AF55;color:#0A1830;font-weight:800;font-size:12px;letter-spacing:1.4px;padding:6px 14px;border-radius:8px}' +
    'h1{margin:6px 0 8px;font-size:40px;line-height:1.1;font-weight:800}h1 span{color:#D4AF55}p{margin:0 auto 22px;max-width:420px;color:#C9D3E6;font-size:15.5px;line-height:1.6}' +
    '.row{display:flex;flex-direction:column;gap:10px;margin:0 auto;max-width:340px}.b{display:block;padding:14px 18px;border-radius:14px;font-weight:700;font-size:15px;text-decoration:none;text-align:center}' +
    '.g{background:linear-gradient(135deg,#C9A24B,#EACF85);color:#0A1830}.o{border:1.5px solid rgba(255,255,255,.35);color:#fff}.f{margin-top:28px;font-size:12.5px;letter-spacing:1.6px;text-transform:uppercase;color:#D4AF55;font-weight:700}';
  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>PPTNEETPGHUB Premium | Coming soon</title><meta name="description" content="PPTNEETPGHUB Premium for NEET PG and INICET is coming soon. Read the latest news and counselling updates meanwhile.">' +
    '<meta name="robots" content="noindex,follow"><link rel="canonical" href="' + h(site) + '/"><meta name="theme-color" content="#0A1830">' +
    '<meta property="og:title" content="PPTNEETPGHUB Premium | Coming soon"><meta property="og:image" content="' + h(site) + '/icon-512.png">' +
    '<link rel="icon" href="/icon-192.png"><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap" rel="stylesheet">' +
    '<style>' + css + '</style></head><body><main class="box"><img class="lg" src="/logo-360.webp" width="150" height="150" alt="PPTNEETPGHUB Premium">' +
    '<div class="tag">NEET PG &middot; INICET</div><h1>Coming <span>soon</span></h1>' +
    '<p>Notes, tests and revision tools are getting ready. Until then, read the latest news and counselling updates.</p>' +
    '<div class="row"><a class="b g" href="/news">Latest news</a><a class="b o" href="/counselling">Counselling updates</a><a class="b o" href="https://t.me/D_V11111" target="_blank" rel="noopener">Message us on Telegram</a></div>' +
    '<div class="f">Pray. Patience. Trust.</div></main></body></html>';
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin' } });
}
// In Coming soon mode: the home page shows the Coming soon page; the other hidden pages send visitors back to it.
function soonRoute(request, env, url) {
  const p = url.pathname;
  if (p === '/' || p === '/index.html') return soonPage(env, url);
  if (p === '/study-tips' || p.startsWith('/study-tips/') || POLICIES[p]) return new Response(null, { status: 302, headers: { Location: url.origin + '/', 'Cache-Control': 'no-store' } });
  if (p === '/api/study-tips') return new Response('{"items":[]}', { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  return null;
}

function fsEq(field, value) {
  return { fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: typeof value === 'boolean' ? { booleanValue: value } : { stringValue: value } } };
}
function decodeNews(doc) {
  const f = doc.fields || {};
  const s = (k) => (f[k] && f[k].stringValue !== undefined ? f[k].stringValue : '');
  const t = (k) => (f[k] && f[k].timestampValue ? f[k].timestampValue : '');
  const date = s('date');
  const n = {
    id: doc.name.split('/').pop(), title: s('title'), slug: s('slug'), type: s('type') || 'update',
    category: s('category') || 'Other', summary: s('summary'), body: s('body'),
    sourceUrl: s('sourceUrl'), sourceName: s('sourceName'), date,
    pinned: !!(f.pinned && f.pinned.booleanValue),
    updatedAt: t('updatedAt') || t('createdAt') || (date ? date + 'T00:00:00Z' : '')
  };
  // Which page it belongs to: news, counselling or tips. Older items without the field are sorted by their type and category.
  const raw = s('section');
  if (n.type === 'tip' || raw === 'tips') n.section = 'tips';
  else if (raw === 'news' || raw === 'counselling') n.section = raw;
  else if (n.slug === 'counselling') n.section = 'counselling';
  else if (n.type === 'guide') n.section = 'news';
  else n.section = LEGACY_COUNSELLING_CATS.indexOf(n.category) > -1 ? 'counselling' : 'news';
  if (n.section === 'counselling' && n.category === 'MCC') n.category = 'Central (MCC)';
  return n;
}
async function fsNews(env, filters) {
  const body = { structuredQuery: { from: [{ collectionId: 'news' }], where: filters.length === 1 ? filters[0] : { compositeFilter: { op: 'AND', filters } }, limit: 300 } };
  const res = await fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID + '/databases/(default)/documents:runQuery', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('Firestore ' + res.status);
  return (await res.json()).filter(r => r.document).map(r => decodeNews(r.document));
}
function sortNews(list) {
  return list.slice().sort((a, b) => (b.date || '').localeCompare(a.date || '') || (b.updatedAt || '').localeCompare(a.updatedAt || ''));
}
const allPublished = (env) => fsNews(env, [fsEq('published', true)]).then(sortNews);

// Fresh for two minutes, and an older copy is kept as a fallback if Firestore is down
async function cachedPage(request, ttl, produce) {
  if (request.__preview) return await produce();
  const cache = caches.default;
  const key = new Request(new URL(request.url).href, { method: 'GET' });
  const hit = await cache.match(key);
  const shortLived = (r, secs) => { const o = new Response(r.body, r); o.headers.set('Cache-Control', 'public, max-age=' + secs); return o; };
  if (hit && (Date.now() - Number(hit.headers.get('x-cached-at') || 0)) / 1000 < ttl) return shortLived(hit, ttl);
  try {
    const res = await produce();
    if (res.status !== 200) return res;
    const text = await res.text();
    const headers = new Headers(res.headers);
    headers.set('x-cached-at', String(Date.now()));
    headers.set('Cache-Control', 'public, max-age=86400');
    await cache.put(key, new Response(text, { status: 200, headers }));
    const out = new Headers(res.headers);
    out.set('Cache-Control', 'public, max-age=' + ttl);
    return new Response(text, { status: 200, headers: out });
  } catch (e) {
    if (hit) return shortLived(hit, 60);
    throw e;
  }
}

// Body text: "## Heading", "- bullet", blank line between paragraphs, **bold**, [text](https://link)
function inlineFmt(raw) {
  let t = h(raw);
  t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (m, label, href) => '<a href="' + href + '" target="_blank" rel="noopener">' + label + '</a>');
  return t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}
function renderBody(text) {
  const out = [];
  String(text || '').replace(/\r/g, '').split(/\n{2,}/).forEach(block => {
    const lines = block.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.length) return;
    if (lines.every(l => /^[-*] /.test(l))) { out.push('<ul>' + lines.map(l => '<li>' + inlineFmt(l.slice(2)) + '</li>').join('') + '</ul>'); return; }
    if (/^## /.test(lines[0])) {
      out.push('<h2>' + inlineFmt(lines[0].slice(3)) + '</h2>');
      const rest = lines.slice(1);
      if (rest.length) out.push(rest.every(l => /^[-*] /.test(l)) ? '<ul>' + rest.map(l => '<li>' + inlineFmt(l.slice(2)) + '</li>').join('') + '</ul>' : '<p>' + rest.map(inlineFmt).join('<br>') + '</p>');
      return;
    }
    out.push('<p>' + lines.map(inlineFmt).join('<br>') + '</p>');
  });
  return out.join('\n');
}
function niceDate(d) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(d || '');
  if (!m) return '';
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}
const clip = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1).trimEnd() + '…' : String(s));

const NEWS_CSS = `*{box-sizing:border-box}body{margin:0;font-family:'Poppins',system-ui,sans-serif;background:#FBF8F1;color:#141A22;-webkit-font-smoothing:antialiased;line-height:1.6}
a{color:#0F8F83}header.top{background:#0A1830;position:sticky;top:0;z-index:5}header.top .in{max-width:1000px;margin:0 auto;padding:12px 18px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.brand{font-weight:800;color:#fff;text-decoration:none;font-size:16px;display:inline-flex;align-items:center}.brand i{font-style:normal;color:#D4AF55;margin:0 4px}
nav.m{display:flex;gap:18px;align-items:center}nav.m a{color:#B4C0D6;text-decoration:none;font-size:14px;font-weight:500}nav.m a:hover{color:#fff}
.btn{display:inline-block;background:linear-gradient(135deg,#C9A24B,#EACF85);color:#0A1830!important;font-weight:700;text-decoration:none;border-radius:20px;padding:8px 16px;font-size:13px}
main{max-width:760px;margin:0 auto;padding:26px 18px 70px}.crumbs{font-size:12.5px;color:#6E7A8A;margin-bottom:14px}.crumbs a{color:#6E7A8A}
h1{font-size:clamp(26px,5vw,36px);line-height:1.18;color:#0A1830;margin:6px 0 10px;letter-spacing:-.3px}h2{font-size:20px;color:#0A1830;margin:26px 0 6px}
.pill{display:inline-block;background:#E8EEF9;color:#27508F;font-size:12px;font-weight:700;border-radius:10px;padding:3px 10px;margin-right:6px}.pill.g{background:#FFF8E8;color:#8A6A1A}.pill.t{background:#DDF3EF;color:#0B6F66}
.meta{font-size:13px;color:#6E7A8A}.lead{font-size:16.5px;color:#3B4656;margin:10px 0 4px}.body p,.body li{font-size:16px}.body ul{padding-left:22px}
.body h2{margin-top:24px}.body p,.body li{line-height:1.65}.src{background:#fff;border:1px solid #E3DCC8;border-left:4px solid #0F8F83;border-radius:12px;padding:12px 14px;margin:22px 0;font-size:14px}
.cta{background:#0A1830;color:#fff;border-radius:18px;padding:22px;margin:30px 0;text-align:center}.cta b{display:block;font-size:19px;margin-bottom:6px}.cta p{color:#A9B6CE;margin:0 0 14px;font-size:14px}
.item{display:block;background:#fff;border:1px solid #E3DCC8;border-radius:14px;padding:14px 16px;margin-bottom:10px;text-decoration:none;color:inherit}.item:hover{border-color:#0F8F83}
.item b{display:block;color:#0A1830;font-size:16px;margin:6px 0 2px}.item span.s{font-size:14px;color:#4B5766}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 18px}.chips a{background:#fff;border:1.5px solid #E3DCC8;color:#4B5766;text-decoration:none;border-radius:20px;padding:6px 13px;font-size:13px;font-weight:600}.chips a.on{background:#0A1830;color:#fff;border-color:#0A1830}
.note{font-size:12.5px;color:#6E7A8A;margin-top:26px}footer{background:#0A1830;color:#A9B6CE;text-align:center;padding:26px 16px;font-size:13px}footer a{color:#D4AF55;margin:0 8px;text-decoration:none}
details.menu{display:none;position:relative}details.menu summary{list-style:none;cursor:pointer;width:40px;height:36px;border:1.5px solid rgba(255,255,255,.3);border-radius:10px;display:grid;place-items:center;color:#fff}
details.menu summary::-webkit-details-marker{display:none}details.menu[open] summary{background:rgba(255,255,255,.12)}
details.menu .panel{position:absolute;right:0;top:calc(100% + 12px);width:min(84vw,270px);background:#0A1830;border:1px solid rgba(212,175,85,.55);border-radius:16px;padding:6px;box-shadow:0 16px 38px rgba(0,0,0,.4)}
details.menu .panel a{display:block;color:#E6EBF5;text-decoration:none;padding:13px 14px;border-radius:10px;font-size:15px;font-weight:500}details.menu .panel a:hover{background:rgba(255,255,255,.08)}
details.menu .panel hr{border:0;border-top:1px solid rgba(255,255,255,.12);margin:4px 6px}
@media(max-width:560px){nav.m a.hide{display:none}details.menu{display:block}.brand i,.brand .pr{display:none}nav.m{gap:10px}header.top .in{padding:12px 14px}}
.btn{white-space:nowrap;line-height:1.3}footer a{white-space:nowrap;display:inline-block;margin-bottom:4px}footer .legal{margin-top:6px}footer .legal a{font-size:12.5px;opacity:.9}.cta-row{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}
@media(max-width:560px){header.top .btn{padding:8px 13px;font-size:12.5px}.cta-row{flex-direction:column;align-items:stretch}.cta-row .btn{display:block;text-align:center;padding:12px 16px;font-size:14px}}
@media(max-width:350px){.brand{font-size:12.5px}.brand img{width:26px!important;height:26px!important;margin-right:6px!important}header.top .in{padding:10px 10px;gap:6px}header.top .btn{padding:7px 10px;font-size:12px}nav.m{gap:6px}details.menu summary{width:34px}}`;

function shell(site, o) {
  return soonify(site, shellFull(site, o));
}
function soonify(site, html) {
  if (!site.soon) return html;
  const drop = (s, x) => s.split(x).join('');      // every copy, not just the first
  let out = html;
  [ '<a class="hide" href="/study-tips">Study tips</a>',
    '<a href="/study-tips">Study tips</a>',
    '<a href="/#features">What you get</a>',
    '<a href="/#pricing">Pricing</a>',
    '<a href="/#faq">FAQ</a>',
    '<hr><a href="/" style="color:#D4AF55;font-weight:700">Member sign in</a>'
  ].forEach(x => { out = drop(out, x); });
  return out
    .replace(/<a class="btn" href="[^"]*">Go Premium<\/a>/g, '')
    .replace(/<div class="legal">.*?<\/div>/g, '')
    .replace(/<div class="cta"><b>Preparing for NEET PG\?<\/b>.*?<\/div>/g, '');
}
function shellFull(site, o) {
  const canonical = site + (o.path || '/');
  const ld = (o.ld || []).map(x => '<script type="application/ld+json">' + JSON.stringify(x).replace(/</g, '\\u003c') + '</script>').join('\n');
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + h(o.title) + '</title><meta name="description" content="' + h(o.desc) + '">' +
    '<link rel="canonical" href="' + h(canonical) + '">' +
    (o.noindex ? '<meta name="robots" content="noindex,follow">' : '<meta name="robots" content="index,follow,max-image-preview:large">') +
    '<meta property="og:type" content="' + (o.ogType || 'website') + '"><meta property="og:title" content="' + h(o.title) + '"><meta property="og:description" content="' + h(o.desc) + '"><meta property="og:url" content="' + h(canonical) + '"><meta property="og:site_name" content="PPTNEETPGHUB">' +
    '<meta name="twitter:card" content="summary"><meta name="theme-color" content="#0A1830">' +
    '<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap" rel="stylesheet">' +
    '<style>' + NEWS_CSS + '</style>' + ld + '</head><body>' +
    '<header class="top"><div class="in"><a class="brand" href="/"><img src="/logo-96.webp" width="30" height="30" alt="" style="border-radius:50%;vertical-align:middle;margin-right:8px">PPTNEETPGHUB<i>&middot;</i><span class="pr">Premium</span></a><nav class="m"><a class="hide" href="/news">News</a><a class="hide" href="/study-tips">Study tips</a><a class="hide" href="/counselling">Counselling</a><a class="btn" href="/#join">Go Premium</a>' +
      '<details class="menu"><summary aria-label="Menu"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></summary><div class="panel">' +
      '<a href="/">Home</a><a href="/#features">What you get</a><a href="/#pricing">Pricing</a><a href="/news">News</a><a href="/study-tips">Study tips</a><a href="/counselling">Counselling</a><a href="/#faq">FAQ</a><hr><a href="/" style="color:#D4AF55;font-weight:700">Member sign in</a></div></details></nav></div></header>' +
    '<main>' + o.body + '</main>' +
    '<footer><div><a href="/">Home</a><a href="/news">News</a><a href="/study-tips">Study tips</a><a href="/counselling">Counselling</a><a href="/#pricing">Pricing</a></div><div class="legal"><a href="/terms">Terms</a><a href="/privacy">Privacy</a><a href="/refund">Refunds</a></div><p>Summaries of official notices. Always confirm dates and rules on the official website before acting.</p></footer><script>document.addEventListener("click",function(e){var d=document.querySelector("details.menu");if(d&&d.open&&!d.contains(e.target))d.open=false;});</script></body></html>';
}
function ctaBox() {
  return '<div class="cta"><b>Preparing for NEET PG?</b><p>Notes, PYQs, flash cards and timed tests, released step by step.</p><a class="btn" href="/#join">Go Premium</a></div>';
}
function htmlResponse(html, status) {
  return new Response(html, { status: status || 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin' } });
}
function notFoundPage(site) {
  return htmlResponse(shell(site, { title: 'Page not found | PPTNEETPGHUB', desc: 'This page was not found.', path: '/news', noindex: true,
    body: '<h1>Page not found</h1><p class="lead">That update does not exist or is no longer published.</p><p><a href="/news">See all updates</a></p>' }), 404);
}
function pathOf(n) {
  if (n.section === 'tips') return '/study-tips/' + h(n.slug);
  if (n.section === 'counselling') return n.slug === 'counselling' ? '/counselling' : '/counselling/' + h(n.slug);
  return '/news/' + h(n.slug);
}
function itemCard(n) {
  return '<a class="item" href="' + pathOf(n) + '"><span class="pill' + (n.type === 'guide' ? ' g' : n.section === 'tips' ? ' t' : '') + '">' + h(n.type === 'guide' ? 'Guide' : n.category) + '</span><span class="meta">' + h(niceDate(n.date)) + '</span><b>' + h(n.title) + '</b><span class="s">' + h(clip(n.summary, 170)) + '</span></a>';
}
function orgLd(site) { return { '@type': 'Organization', name: 'PPTNEETPGHUB', url: site }; }
function crumbLd(site, trail) {
  return { '@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: trail.map((t, i) => ({ '@type': 'ListItem', position: i + 1, name: t[0], item: site + t[1] })) };
}

async function newsListPage(env, url) {
  const site = siteOf(env, url);
  const cat = url.searchParams.get('c') || '';
  const all = await allPublished(env);
  const list = all.filter(n => n.section === 'news' && (!cat || n.category === cat));
  const pinned = list.filter(n => n.pinned && !cat), rest = list.filter(n => !(n.pinned && !cat));
  const chips = '<div class="chips"><a href="/news"' + (!cat ? ' class="on"' : '') + '>All</a>' +
    NEWS_CATEGORIES.map(c => '<a href="/news?c=' + encodeURIComponent(c) + '"' + (cat === c ? ' class="on"' : '') + '>' + h(c) + '</a>').join('') + '</div>';
  const body = '<div class="crumbs"><a href="/">Home</a> › News</div><h1>NEET PG and INICET news</h1>' +
    '<p class="lead">Government and exam notices, seat matrix and other NEET PG and INICET updates, summarised from official sources.</p>' +
    '<p class="meta">Looking for counselling dates and rounds? See <a href="/counselling">Counselling</a>.</p>' + chips +
    (list.length ? pinned.concat(rest).map(itemCard).join('') : '<p>No updates here yet. Check back soon.</p>') + ctaBox();
  return htmlResponse(shell(site, {
    title: 'NEET PG & INICET news and exam updates | PPTNEETPGHUB',
    desc: 'Latest NEET PG and INICET news: government and NBEMS notices, exam updates and seat matrix, with links to the official sources.',
    path: '/news', noindex: !!cat, body,
    ld: [crumbLd(site, [['Home', '/'], ['News', '/news']])]
  }));
}

async function articlePage(env, url, slug) {
  const site = siteOf(env, url);
  const rows = await fsNews(env, [fsEq('slug', slug), fsEq('published', true)]);
  const n = rows[0];
  if (!n) return notFoundPage(site);
  if (n.section !== 'news') return Response.redirect(site + pathOf(n), 301);
  const all = await allPublished(env);
  const related = all.filter(x => x.id !== n.id && x.section === 'news' && x.category === n.category).slice(0, 4);
  const path = '/news/' + n.slug;
  const updated = n.updatedAt ? n.updatedAt.slice(0, 10) : n.date;
  const body = '<div class="crumbs"><a href="/">Home</a> › <a href="/news">News</a> › ' + h(clip(n.title, 50)) + '</div>' +
    '<span class="pill' + (n.type === 'guide' ? ' g' : '') + '">' + h(n.type === 'guide' ? 'Guide' : n.category) + '</span>' +
    '<span class="meta">' + (n.date ? 'Date: ' + h(niceDate(n.date)) : '') + (updated && updated !== n.date ? ' · Last updated: ' + h(niceDate(updated)) : '') + '</span>' +
    '<h1>' + h(n.title) + '</h1><p class="lead">' + h(n.summary) + '</p><div class="body">' + renderBody(n.body) + '</div>' +
    (/^https?:\/\//.test(n.sourceUrl) ? '<div class="src"><b>Official source:</b> <a href="' + h(n.sourceUrl) + '" target="_blank" rel="noopener">' + h(n.sourceName || n.sourceUrl) + '</a><br><span class="meta">Always confirm on the official website.</span></div>' : '') +
    ctaBox() + (related.length ? '<h2>More ' + h(n.category) + ' news</h2>' + related.map(itemCard).join('') : '');
  return htmlResponse(shell(site, {
    title: clip(n.title, 60) + ' | PPTNEETPGHUB', desc: clip(n.summary || n.title, 160), path, ogType: 'article', body,
    ld: [{ '@context': 'https://schema.org', '@type': n.type === 'guide' ? 'Article' : 'NewsArticle', headline: clip(n.title, 110), description: clip(n.summary, 200),
      datePublished: n.date || undefined, dateModified: updated || n.date || undefined, mainEntityOfPage: site + path, author: orgLd(site), publisher: orgLd(site) },
      crumbLd(site, [['Home', '/'], ['News', '/news'], [clip(n.title, 60), path]])]
  }));
}

// ---------- Terms, Privacy and Refund pages ----------
const POLICY_UPDATED = '3 October 2026';
const POLICY_CONTACT = '<p><b>Contact:</b> <a href="https://t.me/D_V11111" target="_blank" rel="noopener">Telegram @D_V11111</a> or <a href="https://wa.me/916355895222" target="_blank" rel="noopener">WhatsApp +91 63558 95222</a>.</p>';
const POLICIES = {
  '/terms': {
    title: 'Terms of Use',
    desc: 'Terms of use for PPTNEETPGHUB Premium: membership, payment, copyright of study resources and acceptable use.',
    body: `<p class="meta">Last updated: ${POLICY_UPDATED}</p>
<p class="lead">These terms apply when you sign in to, buy or use PPTNEETPGHUB Premium ("the website", "we", "us"). By signing in or paying, you agree to them. If you do not agree, please do not use the website.</p>
<h2>1. What we provide</h2>
<p>PPTNEETPGHUB is an online study resource for NEET PG and INICET preparation: notes, PDFs, flashcards, tests, question practice, and study and exam updates. We are an independent educational resource. We are not part of, and not endorsed by, NBEMS, NMC, MCC, AIIMS or any government body.</p>
<h2>2. Your account</h2>
<ul><li>You sign in with your Google account. You are responsible for everything done through your account.</li>
<li>An account is for <b>one person</b>. Do not share your login with anyone.</li>
<li>To protect the content, each account can use a limited number of registered devices (two by default). If you are signed in on more devices, new ones are blocked until you contact us.</li></ul>
<h2>3. Membership and payment</h2>
<ul><li>Membership is bought by UPI payment for the price and period shown on the website when you pay.</li>
<li>After you pay, you submit the UPI transaction ID (UTR). We check it and activate your access. This is done by a person, so it can take some time.</li>
<li>Access lasts for the period shown on your membership. Renewals are offered on the website, and the price and period shown at that time apply.</li>
<li>Please read the <a href="/refund">Refund Policy</a> before paying.</li></ul>
<h2>4. Copyright and ownership of the resources</h2>
<p>All study material on the website is protected by copyright. This includes notes, PDFs, flashcards and their pictures, tests, questions, answers and explanations, study tips, news and counselling write-ups, designs, the website itself, and the PPTNEETPGHUB name and logo. These belong to PPTNEETPGHUB and its creator, or are used with permission. All rights are reserved.</p>
<p>While your membership is active, we give you a limited, personal, non-exclusive and non-transferable licence to view and use the resources for your <b>own exam preparation only</b>.</p>
<p>You must <b>not</b>:</p>
<ul><li>copy, download, photograph, screenshot, screen-record or print the resources to share them with anyone;</li>
<li>send, post or upload them to Telegram, WhatsApp, Google Drive, YouTube, Instagram, any website, app or group, free or paid;</li>
<li>sell, rent, lend, resell or give them away, in full or in part, or use them in any coaching, course, group or business;</li>
<li>share your login, or use automated tools to copy or collect the content;</li>
<li>remove, hide or change any watermark, email mark or notice on the content.</li></ul>
<p>Resources may carry a mark with your email address so that a leaked copy can be traced to the account it came from. If you break these rules, we may close your account at once <b>without any refund</b>, and we may take legal action under the Copyright Act, 1957, the Information Technology Act, 2000 and other applicable laws.</p>
<p>If you believe something on the website copies your own work, please contact us with details and we will look into it quickly.</p>
<h2>5. Using the website properly</h2>
<ul><li>Do not try to break, bypass or overload the website, its payments, device limit or security.</li>
<li>Do not submit false payment details or UTRs.</li>
<li>Be respectful in the Telegram groups. We may remove anyone who spams or abuses others.</li></ul>
<h2>6. No guarantee of results</h2>
<p>We work to keep the content correct and useful, but we do not promise any rank, score, selection or result. Exam rules, dates, seat matrix and counselling details change, and our write-ups are summaries. Always confirm them on the official website before acting. If you find a mistake, use the "Report a mistake" button and we will fix it.</p>
<h2>7. Telegram channels</h2>
<p>Premium members may ask for invite links to our Telegram channels and group. Links are for one person and expire. Telegram's own terms apply there, and the copyright rules above apply to everything posted in them.</p>
<h2>8. Stopping or suspending access</h2>
<p>We may suspend or end access if these terms are broken, if a payment is found to be false or reversed, or if the account is shared. We may also change, pause or improve parts of the website. We will try to give notice of major changes.</p>
<h2>9. Limit of our responsibility</h2>
<p>The website is provided "as it is". To the extent allowed by law, we are not responsible for losses from interruptions, errors, exam outcomes or things outside our control, and our total responsibility for any claim is limited to the amount you paid for your membership.</p>
<h2>10. Changes to these terms</h2>
<p>We may update these terms. The date at the top shows the latest version. If you keep using the website after a change, you accept the new terms.</p>
<h2>11. Law and place of disputes</h2>
<p>These terms follow the laws of India. Any dispute is subject to the courts at Rajkot, Gujarat, India.</p>
<h2>12. Contact</h2>` + POLICY_CONTACT
  },
  '/privacy': {
    title: 'Privacy Policy',
    desc: 'How PPTNEETPGHUB collects, uses and protects your information: Google sign-in, payments, study activity and Telegram.',
    body: `<p class="meta">Last updated: ${POLICY_UPDATED}</p>
<p class="lead">This policy explains what information PPTNEETPGHUB collects when you use the website, why, and what you can ask us to do with it. We keep it to what is needed to run your membership.</p>
<h2>1. What we collect</h2>
<ul><li><b>Sign-in details:</b> your name and email address, from your Google account. We never see your Google password.</li>
<li><b>Payment details:</b> the UPI transaction ID (UTR) you submit, the amount, and the time. We do not receive or store your card or bank account details.</li>
<li><b>Membership details:</b> your start and end dates and notes we add when we approve you.</li>
<li><b>Device details:</b> a random device ID and a short device label (for example "Chrome on Android") so we can enforce the device limit.</li>
<li><b>Study activity:</b> your test attempts and scores, answers, mistake notebook, flashcard progress, the files and tests you open, and where you stopped reading. This powers "My progress" and "Continue where you left off".</li>
<li><b>Reports and messages:</b> mistake reports you send, and messages you send us on Telegram or WhatsApp.</li>
<li><b>Technical data:</b> basic request information such as IP address and browser type, handled by our hosting provider for security and to keep the website running.</li></ul>
<h2>2. How we use it</h2>
<ul><li>To sign you in, check your payment and activate and renew your membership.</li>
<li>To show your progress and save your work across your devices.</li>
<li>To protect the content from sharing, and to trace leaks. Files carry a mark with your email.</li>
<li>To fix mistakes, answer your messages, and improve the website, for example by seeing which files are opened most.</li>
<li>To send you the Telegram invite links you ask for, and to alert us about new payments and problems.</li></ul>
<h2>3. Who handles your data</h2>
<p>We do not sell your personal information and we show no ads. We use these services to run the website, and your data is processed by them under their own terms:</p>
<ul><li><b>Google (Firebase):</b> sign-in and the database that stores your account, progress and payments.</li>
<li><b>Cloudflare:</b> hosting, security and private storage of the study files.</li>
<li><b>Telegram:</b> alerts to us about payments and problems, and the optional member channels.</li>
<li><b>GitHub:</b> where the website's code is kept. It does not hold student data.</li></ul>
<p>Your data may be stored on servers outside India. We may also share information if the law requires it.</p>
<h2>4. Cookies and local storage</h2>
<p>We do not use advertising or tracking cookies. The website stores small items on your device, such as your device ID, your test in progress, your notebook and where you stopped reading, so the website works smoothly. Clearing your browser data removes them.</p>
<h2>5. How long we keep it</h2>
<p>We keep your account, payment and progress records while your membership is active and for a reasonable time afterwards, for accounts, disputes and the law. You can ask us to delete your data (see below).</p>
<h2>6. Your choices</h2>
<ul><li>You can ask us to show, correct or delete the personal information we hold about you.</li>
<li>You can stop using the website at any time and clear the data stored on your device.</li>
<li>Deleting your data may end your access, and payments already made are covered by the <a href="/refund">Refund Policy</a>.</li></ul>
<h2>7. Security</h2>
<p>Files are kept private and are only given to signed-in members with active access. Access to the database is limited by rules, and each student can see only their own progress. No online service is completely secure, so please keep your Google account safe.</p>
<h2>8. Children</h2>
<p>The website is made for medical graduates preparing for postgraduate entrance exams. It is not meant for anyone under 18.</p>
<h2>9. Changes</h2>
<p>We may update this policy. The date at the top shows the latest version.</p>
<h2>10. Contact</h2>` + POLICY_CONTACT
  },
  '/refund': {
    title: 'Refund Policy',
    desc: 'Refund policy for PPTNEETPGHUB Premium: when a refund is given, how to ask for one and how long it takes.',
    body: `<p class="meta">Last updated: ${POLICY_UPDATED}</p>
<p class="lead">PPTNEETPGHUB Premium is digital study material that you can use as soon as your access is activated. Please read this before you pay.</p>
<h2>1. General rule</h2>
<p>Because the content is delivered digitally and you can view it right away, <b>we do not give refunds once your access has been activated</b>, and we do not refund for reasons such as a change of mind, not having time to study, or a change in your exam plans.</p>
<h2>2. When we do refund</h2>
<ul><li><b>Duplicate payment:</b> you paid more than once for the same membership. We refund the extra payment.</li>
<li><b>Payment taken but no access:</b> money left your account, but your access was not activated within 48 hours of you submitting the payment, and we cannot sort it out.</li>
<li><b>Technical problem on our side:</b> you cannot use the website because of a fault that we could not fix within 7 days of you telling us.</li>
<li><b>Wrong amount or wrong account:</b> you paid the wrong amount by mistake. We refund the difference or the payment, as is correct.</li></ul>
<h2>3. When we do not refund</h2>
<ul><li>If your account is closed because the copyright or use rules in the <a href="/terms">Terms of Use</a> were broken, for example sharing the login or the content.</li>
<li>If the payment details you submitted were false.</li>
<li>For renewals after the membership period has started.</li></ul>
<h2>4. How to ask</h2>
<p>Message us within <b>7 days</b> of the payment. Please send the email you signed in with, the UTR, the date and amount, and a screenshot of the payment. We reply as soon as we can.</p>
<h2>5. How long it takes</h2>
<p>Approved refunds are sent back by UPI to the account that paid, usually within 7 working days. Your bank may take a little longer to show it.</p>
<h2>6. Questions</h2>` + POLICY_CONTACT
  }
};
async function policyPage(env, url, path) {
  const site = siteOf(env, url), p = POLICIES[path];
  const body = '<div class="crumbs"><a href="/">Home</a> › ' + h(p.title) + '</div><h1>' + h(p.title) + '</h1><div class="body">' + p.body + '</div>';
  return htmlResponse(shell(site, { title: p.title + ' | PPTNEETPGHUB', desc: p.desc, path, body, ld: [crumbLd(site, [['Home', '/'], [p.title, path]])] }));
}

// ---------- Study tips (the blog) ----------
function tipNotFound(site) {
  return htmlResponse(shell(site, { title: 'Page not found | PPTNEETPGHUB', desc: 'This page was not found.', path: '/study-tips', noindex: true,
    body: '<h1>Page not found</h1><p class="lead">That study tip does not exist or is no longer published.</p><p><a href="/study-tips">See all study tips</a></p>' }), 404);
}
function tipsCta() {
  return '<div class="cta"><b>Turn tips into marks.</b><p>Try 10 free questions, then practise by subject with instant answers.</p><div class="cta-row"><a class="btn" href="/#sampleSec">Try the free sample</a><a class="btn" href="/#join">Go Premium</a></div></div>';
}
const allTips = (env) => allPublished(env).then(list => list.filter(n => n.section === 'tips'));

async function tipsListPage(env, url) {
  const site = siteOf(env, url);
  const cat = url.searchParams.get('c') || '';
  const all = await allTips(env);
  const list = all.filter(n => !cat || n.category === cat);
  const pinned = list.filter(n => n.pinned && !cat), rest = list.filter(n => !(n.pinned && !cat));
  const chips = '<div class="chips"><a href="/study-tips"' + (!cat ? ' class="on"' : '') + '>All</a>' +
    TIP_CATEGORIES.map(c => '<a href="/study-tips?c=' + encodeURIComponent(c) + '"' + (cat === c ? ' class="on"' : '') + '>' + h(c) + '</a>').join('') + '</div>';
  const body = '<div class="crumbs"><a href="/">Home</a> › Study tips</div><h1>NEET PG study tips</h1>' +
    '<p class="lead">Simple, practical advice on planning, revision, mock tests and staying consistent.</p>' + chips +
    (list.length ? pinned.concat(rest).map(itemCard).join('') : '<p>No study tips here yet. Check back soon.</p>') + tipsCta();
  return htmlResponse(shell(site, {
    title: 'NEET PG study tips: revision, mock tests, planning | PPTNEETPGHUB',
    desc: 'Practical NEET PG and INICET study tips: how to plan revision, use mock tests, remember more and stay consistent through a long preparation.',
    path: '/study-tips', noindex: !!cat, body,
    ld: [crumbLd(site, [['Home', '/'], ['Study tips', '/study-tips']])]
  }));
}

async function tipPage(env, url, slug) {
  const site = siteOf(env, url);
  const rows = await fsNews(env, [fsEq('slug', slug), fsEq('published', true)]);
  const n = rows[0];
  if (!n || n.section !== 'tips') return tipNotFound(site);
  const all = await allTips(env);
  const same = all.filter(x => x.id !== n.id && x.category === n.category);
  const related = same.concat(all.filter(x => x.id !== n.id && x.category !== n.category)).slice(0, 4);
  const path = '/study-tips/' + n.slug;
  const updated = n.updatedAt ? n.updatedAt.slice(0, 10) : n.date;
  const body = '<div class="crumbs"><a href="/">Home</a> › <a href="/study-tips">Study tips</a> › ' + h(clip(n.title, 50)) + '</div>' +
    '<span class="pill t">' + h(n.category) + '</span>' +
    '<span class="meta">' + (n.date ? h(niceDate(n.date)) : '') + (updated && updated !== n.date ? ' · Updated: ' + h(niceDate(updated)) : '') + '</span>' +
    '<h1>' + h(n.title) + '</h1><p class="lead">' + h(n.summary) + '</p><div class="body">' + renderBody(n.body) + '</div>' +
    (/^https?:\/\//.test(n.sourceUrl) ? '<div class="src"><b>Source:</b> <a href="' + h(n.sourceUrl) + '" target="_blank" rel="noopener">' + h(n.sourceName || n.sourceUrl) + '</a></div>' : '') +
    tipsCta() + (related.length ? '<h2>More study tips</h2>' + related.map(itemCard).join('') : '');
  return htmlResponse(shell(site, {
    title: clip(n.title, 60) + ' | PPTNEETPGHUB', desc: clip(n.summary || n.title, 160), path, ogType: 'article', body,
    ld: [{ '@context': 'https://schema.org', '@type': 'Article', headline: clip(n.title, 110), description: clip(n.summary, 200),
      datePublished: n.date || undefined, dateModified: updated || n.date || undefined, mainEntityOfPage: site + path, author: orgLd(site), publisher: orgLd(site) },
      crumbLd(site, [['Home', '/'], ['Study tips', '/study-tips'], [clip(n.title, 60), path]])]
  }));
}
async function tipsLatestJson(env, url) {
  const n = Math.max(1, Math.min(10, parseInt(url.searchParams.get('limit') || '3', 10) || 3));
  const all = (await allTips(env)).slice(0, n);
  return new Response(JSON.stringify({ items: all.map(x => ({ title: x.title, slug: x.slug, category: x.category, date: x.date })) }), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } });
}

async function counsellingPage(env, url) {
  const site = siteOf(env, url);
  const cat = url.searchParams.get('c') || '';
  const all = await allPublished(env);
  const guide = all.find(n => n.slug === 'counselling' && n.section === 'counselling');
  const items = all.filter(n => n.section === 'counselling' && n.slug !== 'counselling' && (!cat || n.category === cat));
  const pinned = items.filter(n => n.pinned && !cat), rest = items.filter(n => !(n.pinned && !cat));
  const updated = guide && guide.updatedAt ? guide.updatedAt.slice(0, 10) : '';
  const chips = '<div class="chips"><a href="/counselling#updates"' + (!cat ? ' class="on"' : '') + '>All</a>' +
    COUNSELLING_CATEGORIES.map(c => '<a href="/counselling?c=' + encodeURIComponent(c) + '#updates"' + (cat === c ? ' class="on"' : '') + '>' + h(c) + '</a>').join('') + '</div>';
  const body = '<div class="crumbs"><a href="/">Home</a> › Counselling</div>' +
    '<h1>' + h(guide ? guide.title : 'NEET PG counselling: rounds, seat matrix and updates') + '</h1>' +
    (guide ? '<p class="meta">' + (updated ? 'Last updated: ' + h(niceDate(updated)) : '') + '</p><p class="lead">' + h(guide.summary) + '</p><div class="body">' + renderBody(guide.body) + '</div>' +
      (/^https?:\/\//.test(guide.sourceUrl) ? '<div class="src"><b>Official source:</b> <a href="' + h(guide.sourceUrl) + '" target="_blank" rel="noopener">' + h(guide.sourceName || guide.sourceUrl) + '</a></div>' : '')
      : '<p class="lead">Counselling dates, rounds and seat matrix updates are listed below as soon as they are published.</p>') +
    '<h2 id="updates">Counselling updates</h2>' + chips +
    (items.length ? pinned.concat(rest).slice(0, 60).map(itemCard).join('') : '<p>No counselling updates here yet. Check back soon.</p>') +
    '<p><a href="/news">Government and exam news →</a></p>' + ctaBox();
  return htmlResponse(shell(site, {
    title: clip(guide ? guide.title : 'NEET PG counselling: rounds, seat matrix, updates', 60) + ' | PPTNEETPGHUB',
    desc: clip(guide && guide.summary ? guide.summary : 'NEET PG counselling guide: central (MCC) and state counselling rounds, seat matrix, documents and the latest updates with official links.', 160),
    path: '/counselling', noindex: !!cat, body, ld: [crumbLd(site, [['Home', '/'], ['Counselling', '/counselling']])]
  }));
}

function counsellingNotFound(site) {
  return htmlResponse(shell(site, { title: 'Page not found | PPTNEETPGHUB', desc: 'This page was not found.', path: '/counselling', noindex: true,
    body: '<h1>Page not found</h1><p class="lead">That counselling update does not exist or is no longer published.</p><p><a href="/counselling">See all counselling updates</a></p>' }), 404);
}
async function counsellingItemPage(env, url, slug) {
  const site = siteOf(env, url);
  const rows = await fsNews(env, [fsEq('slug', slug), fsEq('published', true)]);
  const n = rows[0];
  if (!n) return counsellingNotFound(site);
  if (n.section !== 'counselling') return Response.redirect(site + pathOf(n), 301);
  if (n.slug === 'counselling') return Response.redirect(site + '/counselling', 301);
  const all = await allPublished(env);
  const related = all.filter(x => x.id !== n.id && x.section === 'counselling' && x.slug !== 'counselling' && x.category === n.category).slice(0, 4);
  const path = '/counselling/' + n.slug;
  const updated = n.updatedAt ? n.updatedAt.slice(0, 10) : n.date;
  const body = '<div class="crumbs"><a href="/">Home</a> › <a href="/counselling">Counselling</a> › ' + h(clip(n.title, 50)) + '</div>' +
    '<span class="pill' + (n.type === 'guide' ? ' g' : '') + '">' + h(n.type === 'guide' ? 'Guide' : n.category) + '</span>' +
    '<span class="meta">' + (n.date ? 'Date: ' + h(niceDate(n.date)) : '') + (updated && updated !== n.date ? ' · Last updated: ' + h(niceDate(updated)) : '') + '</span>' +
    '<h1>' + h(n.title) + '</h1><p class="lead">' + h(n.summary) + '</p><div class="body">' + renderBody(n.body) + '</div>' +
    (/^https?:\/\//.test(n.sourceUrl) ? '<div class="src"><b>Official source:</b> <a href="' + h(n.sourceUrl) + '" target="_blank" rel="noopener">' + h(n.sourceName || n.sourceUrl) + '</a><br><span class="meta">Always confirm on the official website.</span></div>' : '') +
    ctaBox() + (related.length ? '<h2>More ' + h(n.category) + ' updates</h2>' + related.map(itemCard).join('') : '<p><a href="/counselling">All counselling updates →</a></p>');
  return htmlResponse(shell(site, {
    title: clip(n.title, 60) + ' | PPTNEETPGHUB', desc: clip(n.summary || n.title, 160), path, ogType: 'article', body,
    ld: [{ '@context': 'https://schema.org', '@type': n.type === 'guide' ? 'Article' : 'NewsArticle', headline: clip(n.title, 110), description: clip(n.summary, 200),
      datePublished: n.date || undefined, dateModified: updated || n.date || undefined, mainEntityOfPage: site + path, author: orgLd(site), publisher: orgLd(site) },
      crumbLd(site, [['Home', '/'], ['Counselling', '/counselling'], [clip(n.title, 60), path]])]
  }));
}

async function sitemapXml(env, url) {
  const site = siteOf(env, url);
  const everything = await allPublished(env);
  const news = everything.filter(n => n.section === 'news');
  const coun = everything.filter(n => n.section === 'counselling' && n.slug !== 'counselling');
  const tips = everything.filter(n => n.section === 'tips');
  const guide = everything.find(n => n.slug === 'counselling' && n.section === 'counselling');
  const last = (l) => (l.length ? (l[0].updatedAt || '').slice(0, 10) : '');
  const rows = site.soon
    ? [{ loc: '/news', mod: last(news) }, { loc: '/counselling', mod: guide ? (guide.updatedAt || '').slice(0, 10) : last(coun) }]
    : [{ loc: '/', mod: '' }, { loc: '/terms', mod: '' }, { loc: '/privacy', mod: '' }, { loc: '/refund', mod: '' }, { loc: '/news', mod: last(news) }, { loc: '/counselling', mod: guide ? (guide.updatedAt || '').slice(0, 10) : last(coun) }, { loc: '/study-tips', mod: last(tips) }];
  news.forEach(n => rows.push({ loc: '/news/' + n.slug, mod: (n.updatedAt || n.date || '').slice(0, 10) }));
  coun.forEach(n => rows.push({ loc: '/counselling/' + n.slug, mod: (n.updatedAt || n.date || '').slice(0, 10) }));
  if (!site.soon) tips.forEach(n => rows.push({ loc: '/study-tips/' + n.slug, mod: (n.updatedAt || n.date || '').slice(0, 10) }));
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    rows.map(r => '<url><loc>' + h(site + r.loc) + '</loc>' + (r.mod ? '<lastmod>' + h(r.mod) + '</lastmod>' : '') + '</url>').join('\n') + '\n</urlset>';
  return new Response(xml, { status: 200, headers: { 'Content-Type': 'application/xml; charset=utf-8' } });
}
function robotsTxt(env, url) {
  const site = siteOf(env, url);
  return new Response('User-agent: *\nAllow: /\nDisallow: /admin.html\nDisallow: /api/\n\nSitemap: ' + site + '/sitemap.xml\n', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
}
async function latestJson(env, url) {
  const n = Math.max(1, Math.min(10, parseInt(url.searchParams.get('limit') || '3', 10) || 3));
  const all = (await allPublished(env)).filter(x => x.section === 'news').slice(0, n);
  return new Response(JSON.stringify({ items: all.map(x => ({ title: x.title, slug: x.slug, category: x.category, date: x.date })) }), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' } });
}

async function handlePublic(request, env, url) {
  const p = url.pathname;
  if (p.length > 1 && p.endsWith('/')) return Response.redirect(url.origin + p.replace(/\/+$/, '') + url.search, 301);
  if (p === '/robots.txt') return robotsTxt(env, url);
  const site = siteOf(env, url);
  try {
    if (p === '/sitemap.xml') return await cachedPage(request, FRESH_SECONDS, () => sitemapXml(env, url));
    if (p === '/api/news') return await cachedPage(request, 60, () => latestJson(env, url));
    if (POLICIES[p]) return await cachedPage(request, 3600, () => policyPage(env, url, p));
    if (p === '/api/study-tips') return await cachedPage(request, 60, () => tipsLatestJson(env, url));
    if (p === '/study-tips') return await cachedPage(request, FRESH_SECONDS, () => tipsListPage(env, url));
    const tm = /^\/study-tips\/([a-z0-9-]{3,80})$/.exec(p);
    if (tm) return await cachedPage(request, FRESH_SECONDS, () => tipPage(env, url, tm[1]));
    if (p.startsWith('/study-tips/')) return tipNotFound(site);
    if (p === '/news') return await cachedPage(request, FRESH_SECONDS, () => newsListPage(env, url));
    if (p === '/counselling') return await cachedPage(request, FRESH_SECONDS, () => counsellingPage(env, url));
    const cm = /^\/counselling\/([a-z0-9-]{3,80})$/.exec(p);
    if (cm) return await cachedPage(request, FRESH_SECONDS, () => counsellingItemPage(env, url, cm[1]));
    if (p.startsWith('/counselling/')) return counsellingNotFound(site);
    const m = /^\/news\/([a-z0-9-]{3,80})$/.exec(p);
    if (m) return await cachedPage(request, FRESH_SECONDS, () => articlePage(env, url, m[1]));
    if (p.startsWith('/news/')) return notFoundPage(site);
  } catch (e) {
    console.error('News page failed', e);
    await tgAlert(env, 'public-pages', 'The public pages (/news, /counselling, /study-tips) could not load from the database: ' + String(e && e.message).slice(0, 120));
    return htmlResponse(shell(site, { title: 'Temporarily unavailable | PPTNEETPGHUB', desc: 'Please try again in a moment.', path: '/news', noindex: true,
      body: '<h1>Temporarily unavailable</h1><p class="lead">Updates could not be loaded just now. Please try again in a minute.</p><p><a href="/">Back to home</a></p>' }), 503);
  }
  return null;
}


// ---------- Alerts to the admin on Telegram when something breaks ----------
const alertSeen = new Map();   // key -> time, so the same problem is not repeated for a while
async function tgAlert(env, key, text, gapMs) {
  try {
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return false;
    const gap = gapMs === undefined ? 30 * 60 * 1000 : gapMs;
    if (Date.now() - (alertSeen.get(key) || 0) < gap) return false;
    alertSeen.set(key, Date.now()); trimMap(alertSeen, 200);
    const site = String(env.SITE_URL || '').replace(/\/$/, '');
    return await tgSend(env, env.TELEGRAM_CHAT_ID, '\u26A0\uFE0F PPTNEETPGHUB problem\n' + text, site ? site + '/admin.html' : '', 'Open admin panel');
  } catch (e) { return false; }
}

// The website tells us when something failed for a student (payment not saved, library not loading).
const PROBLEM_LABELS = {
  'payment-save': 'A student could not save a payment',
  'library-load': 'A paid member\'s library did not load',
  'attempt-save': 'A test result could not be saved',
  'other': 'The website reported a problem'
};
const problemByUser = new Map();   // email -> times, per hour
let problemGlobal = [];
async function handleReportProblem(request, env) {
  const user = await requireUser(request, env);
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return json({ ok: true, skipped: true });
  let body = {}; try { body = await request.json(); } catch (e) {}
  const kind = PROBLEM_LABELS[body.kind] ? body.kind : 'other';
  const now = Date.now(), hour = 3600000;
  const mine = (problemByUser.get(user.email) || []).filter(t => now - t < hour);
  problemGlobal = problemGlobal.filter(t => now - t < hour);
  if (mine.length >= 3 || problemGlobal.length >= 20) return json({ ok: true, skipped: true });
  mine.push(now); problemGlobal.push(now); problemByUser.set(user.email, mine); trimMap(problemByUser, 500);
  const detail = String(body.detail || '').replace(/[\r\n]+/g, ' ').slice(0, 200);
  const sent = await tgSend(env, env.TELEGRAM_CHAT_ID, '\u26A0\uFE0F PPTNEETPGHUB problem\n' + PROBLEM_LABELS[kind] + '\nStudent: ' + user.email + (detail ? '\nDetail: ' + detail : ''), String(env.SITE_URL || '').replace(/\/$/, '') + '/admin.html', 'Open admin panel').catch(() => false);
  return json({ ok: true, sent: !!sent });
}

// Every 10 minutes: is the database reachable, is the file storage working? Alert after two failures in a row.
async function runHealth(env) {
  const checks = { firestore: false, r2: false };
  try {
    const r = await fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID + '/databases/(default)/documents/config/pricing');
    checks.firestore = r.status === 200 || r.status === 404;
  } catch (e) {}
  let prev = { fails: {}, alerted: {} };
  try { const o = await env.FILES.get('system/health.json'); if (o) prev = JSON.parse(await o.text()); checks.r2 = true; } catch (e) {}
  if (!checks.r2) { try { await env.FILES.list({ limit: 1 }); checks.r2 = true; } catch (e) {} }
  const next = { fails: {}, alerted: {}, at: Date.now() };
  const names = { firestore: 'The database (Firestore) is not reachable from the website', r2: 'The private file storage (R2) is not working' };
  for (const k of Object.keys(checks)) {
    const fails = checks[k] ? 0 : ((prev.fails && prev.fails[k]) || 0) + 1;
    next.fails[k] = fails;
    const wasAlerted = !!(prev.alerted && prev.alerted[k]);
    if (fails >= 2 && !wasAlerted) { await tgAlert(env, 'health:' + k, names[k] + '. Students may not be able to use the website.', 0); next.alerted[k] = true; }
    else if (fails >= 2) next.alerted[k] = true;
    else if (checks[k] && wasAlerted) await tgAlert(env, 'health-ok:' + k, 'Recovered: ' + names[k].replace('is not', 'was not').replace(' not ', ' not ') + ', but it is working again.', 0);
  }
  try { await env.FILES.put('system/health.json', JSON.stringify(next), { httpMetadata: { contentType: 'application/json' } }); } catch (e) {}
  return checks;
}

// Admin: which settings are in place, plus a test message to Telegram
async function handleAdminHealth(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');
  if (request.method === 'POST') {
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return json({ ok: false, reason: 'Telegram is not set up: add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.' });
    const ok = await tgSend(env, env.TELEGRAM_CHAT_ID, '\u2705 Test alert from PPTNEETPGHUB. Alerts to this chat are working.', String(env.SITE_URL || '').replace(/\/$/, '') + '/admin.html', 'Open admin panel');
    return json({ ok, reason: ok ? '' : 'Telegram refused the message. Check the bot token and that the bot can write to the chat.' });
  }
  let r2 = false; try { await env.FILES.list({ limit: 1 }); r2 = true; } catch (e) {}
  let fire = false;
  try { const r = await fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID + '/databases/(default)/documents/config/pricing'); fire = r.status === 200 || r.status === 404; } catch (e) {}
  let health = null; try { const o = await env.FILES.get('system/health.json'); if (o) health = JSON.parse(await o.text()); } catch (e) {}
  const set = (k) => !!env[k];
  return json({
    ok: true, r2, firestore: fire,
    secrets: { TELEGRAM_BOT_TOKEN: set('TELEGRAM_BOT_TOKEN'), TELEGRAM_CHAT_ID: set('TELEGRAM_CHAT_ID'), TG_CHAT_PREMIUM: set('TG_CHAT_PREMIUM'), TG_CHAT_INICET: set('TG_CHAT_INICET'), TG_CHAT_DISCUSS: set('TG_CHAT_DISCUSS'), TELEGRAM_ANNOUNCE_CHAT_ID: set('TELEGRAM_ANNOUNCE_CHAT_ID') },
    vars: { SITE_URL: set('SITE_URL'), ADMIN_EMAIL: set('ADMIN_EMAIL'), PROJECT_ID: set('PROJECT_ID') },
    cronLastRun: health && health.at ? health.at : 0,
    comingSoon: isOn(env.COMING_SOON), previewKey: !!(env.PREVIEW_KEY && String(env.PREVIEW_KEY).length >= 6)
  });
}

// ---------- Backups kept in the private file storage ----------
const BACKUP_KEEP = 12, BACKUP_MAX_BYTES = 40 * 1024 * 1024;
async function handleBackup(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');
  const reqKey = url.searchParams.get('key');
  const okKey = (k) => /^backups\/pptneetpghub-backup-\d{8}-\d{6}\.json$/.test(String(k || ''));
  if (request.method === 'POST') {
    const text = await request.text();
    if (!text || text.length > BACKUP_MAX_BYTES) throw new HttpError(413, 'The backup is empty or too large');
    let data; try { data = JSON.parse(text); } catch (e) { throw new HttpError(400, 'Not a valid backup'); }
    if (!data || data.app !== 'pptneetpghub' || !data.collections || typeof data.collections !== 'object') throw new HttpError(400, 'Not a PPTNEETPGHUB backup');
    const d = new Date(), z = (n, l) => String(n).padStart(l || 2, '0');
    const key = 'backups/pptneetpghub-backup-' + d.getUTCFullYear() + z(d.getUTCMonth() + 1) + z(d.getUTCDate()) + '-' + z(d.getUTCHours()) + z(d.getUTCMinutes()) + z(d.getUTCSeconds()) + '.json';
    await env.FILES.put(key, text, { httpMetadata: { contentType: 'application/json' } });
    const all = (await env.FILES.list({ prefix: 'backups/', limit: 200 })).objects.map(o => o.key).filter(okKey).sort().reverse();
    for (const old of all.slice(BACKUP_KEEP)) await env.FILES.delete(old);
    return json({ ok: true, key, size: text.length, kept: Math.min(all.length, BACKUP_KEEP) });
  }
  if (request.method === 'DELETE') {
    if (!okKey(reqKey)) throw new HttpError(400, 'Invalid backup name');
    await env.FILES.delete(reqKey);
    return json({ ok: true });
  }
  if (reqKey) {
    if (!okKey(reqKey)) throw new HttpError(400, 'Invalid backup name');
    const o = await env.FILES.get(reqKey);
    if (!o) throw new HttpError(404, 'Backup not found');
    return new Response(o.body, { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="' + reqKey.split('/').pop() + '"', 'Cache-Control': 'private, no-store' } });
  }
  const list = (await env.FILES.list({ prefix: 'backups/', limit: 200 })).objects.filter(o => okKey(o.key)).map(o => ({ key: o.key, size: o.size, uploaded: o.uploaded ? new Date(o.uploaded).getTime() : 0 }));
  list.sort((a, b) => (a.key < b.key ? 1 : -1));
  return json({ ok: true, backups: list });
}

// ---------- Telegram helpers ----------
async function tgCall(env, method, payload) {
  const res = await fetch('https://api.telegram.org/bot' + env.TELEGRAM_BOT_TOKEN + '/' + method, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { ok: res.ok && !!(data && data.ok !== false), data };
}
async function tgSend(env, chatId, text, url, label) {
  const body = { chat_id: chatId, text: String(text).slice(0, 4000), disable_web_page_preview: true };
  if (url) body.reply_markup = { inline_keyboard: [[{ text: label || 'Open', url }]] };
  return (await tgCall(env, 'sendMessage', body)).ok;
}
async function requireMember(request, env) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) {
    const st = await memberStatus(user, env);
    if (st === 'expired') throw new HttpError(403, 'Your membership has ended. Renew to continue.', 'expired');
    if (st !== 'active') throw new HttpError(403, 'Premium members only', 'members');
    if (!(await deviceAllowed(user, request.headers.get('X-Device-Id'), env))) throw new HttpError(403, 'This device is not registered for your account.', 'device');
  }
  return user;
}

// ---------- New-content announcements (scheduled) ----------
// The admin panel queues a post; a cron job sends it to the Telegram channel when its time comes.
// Needs the secret TELEGRAM_ANNOUNCE_CHAT_ID (the bot must be an admin of that channel).
const MAX_ANNOUNCE_AGE = 7 * 86400000;

async function handleAnnounce(request, env) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');
  let body = null;
  try { body = await request.json(); } catch (e) { throw new HttpError(400, 'Bad request'); }
  const items = (Array.isArray(body && body.items) ? body.items : []).slice(0, 100).map(x => ({
    title: String((x && x.title) || '').slice(0, 120), subject: String((x && x.subject) || '').slice(0, 40), tab: String((x && x.tab) || '').slice(0, 40)
  })).filter(x => x.title);
  if (!items.length) throw new HttpError(400, 'Nothing to announce');
  let at = Number(body.at) || Date.now();
  at = Math.min(Math.max(at, Date.now() - 60000), Date.now() + 90 * 86400000);
  const key = 'announce-queue/' + String(Math.floor(at)).padStart(14, '0') + '-' + randomId() + '.json';
  await env.FILES.put(key, JSON.stringify({ at, items }), { httpMetadata: { contentType: 'application/json' } });
  return json({ ok: true, queued: items.length, configured: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_ANNOUNCE_CHAT_ID) });
}

function buildAnnouncement(items, site) {
  const groups = new Map();
  items.forEach(x => { const k = (x.subject || 'General') + ' · ' + (x.tab || 'Update'); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(x.title); });
  let t = 'New on PPTNEETPGHUB\n';
  groups.forEach((titles, k) => {
    t += '\n' + k + ': ' + titles.length + ' new\n';
    const shown = titles.slice(0, 3).join(', ');
    t += shown + (titles.length > 3 ? ' and ' + (titles.length - 3) + ' more' : '') + '\n';
  });
  return t + '\nOpen your library: ' + site;
}

async function runAnnouncements(env) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_ANNOUNCE_CHAT_ID) return { sent: 0, reason: 'not configured' };
  const site = String(env.SITE_URL || '').replace(/\/$/, '') || 'https://pptneetpghub.com';
  const list = await env.FILES.list({ prefix: 'announce-queue/', limit: 50 });
  let sent = 0;
  for (const obj of list.objects) {
    const m = /announce-queue\/(\d{14})-/.exec(obj.key);
    if (!m) continue;
    const at = Number(m[1]);
    if (at > Date.now()) continue;
    try {
      const o = await env.FILES.get(obj.key);
      if (!o) continue;
      const data = JSON.parse(await o.text());
      const ok = await tgSend(env, env.TELEGRAM_ANNOUNCE_CHAT_ID, buildAnnouncement(data.items || [], site), site, 'Open the library');
      if (ok) { await env.FILES.delete(obj.key); sent++; }
      else if (Date.now() - at > MAX_ANNOUNCE_AGE) await env.FILES.delete(obj.key);   // give up after a week
    } catch (e) { console.error('Announcement failed', e); }
  }
  return { sent };
}

// ---------- One-time Telegram invite links for members ----------
// Needs TELEGRAM_BOT_TOKEN plus at least one of TG_CHAT_PREMIUM, TG_CHAT_INICET, TG_CHAT_DISCUSS
// (the bot must be an admin with the right to invite users in each of them).
const TG_ISSUES_MAX = 2, TG_ISSUES_WINDOW = 30 * 86400000, TG_LINK_LIFE = 2 * 86400;

async function handleTelegramLinks(request, env, url) {
  const user = await requireMember(request, env);
  const chats = [['Premium channel', env.TG_CHAT_PREMIUM], ['INICET bonus channel', env.TG_CHAT_INICET], ['Discussion group', env.TG_CHAT_DISCUSS]].filter(x => x[1]);

  if (request.method === 'DELETE') {                  // admin: let a member get fresh links
    if (!user.isAdmin) throw new HttpError(403, 'Admin only');
    const email = String(url.searchParams.get('email') || '').toLowerCase();
    if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new HttpError(400, 'Invalid email');
    await env.FILES.delete('tg-invites/' + email + '.json');
    return json({ ok: true });
  }
  if (!env.TELEGRAM_BOT_TOKEN || !chats.length) return json({ ok: false, reason: 'not configured' });

  const key = 'tg-invites/' + user.email + '.json';
  let issued = [];
  try { const o = await env.FILES.get(key); if (o) issued = (JSON.parse(await o.text()).issued || []).filter(t => Date.now() - t < TG_ISSUES_WINDOW); } catch (e) {}
  if (url.searchParams.get('check')) {                // only tells the site whether to show the button
    return json({ ok: true, configured: true, remaining: user.isAdmin ? TG_ISSUES_MAX : Math.max(0, TG_ISSUES_MAX - issued.length), next: issued.length ? Math.min.apply(null, issued) + TG_ISSUES_WINDOW : 0 });
  }
  if (!user.isAdmin && issued.length >= TG_ISSUES_MAX) return json({ ok: false, reason: 'limit', next: Math.min.apply(null, issued) + TG_ISSUES_WINDOW });

  const links = [];
  for (const c of chats) {
    const r = await tgCall(env, 'createChatInviteLink', { chat_id: c[1], name: ('web ' + user.email).slice(0, 32), expire_date: Math.floor(Date.now() / 1000) + TG_LINK_LIFE, member_limit: 1 });
    if (r.ok && r.data && r.data.result && r.data.result.invite_link) links.push({ label: c[0], url: r.data.result.invite_link });
    else console.error('Invite link failed for', c[0]);
  }
  if (!links.length) throw new HttpError(502, 'Could not create the links. Please message us.');
  issued.push(Date.now());
  await env.FILES.put(key, JSON.stringify({ issued }), { httpMetadata: { contentType: 'application/json' } });
  return json({ ok: true, links, remaining: Math.max(0, TG_ISSUES_MAX - issued.length), hours: TG_LINK_LIFE / 3600 });
}

// ---------- Alert for a new mistake report ----------
const notifiedReport = new Map();
const lastReport = new Map();
async function handleNotifyReport(request, env, url) {
  const user = await requireUser(request, env);
  let body = null;
  try { body = await request.json(); } catch (e) { throw new HttpError(400, 'Bad request'); }
  const id = String((body && body.id) || '');
  if (!/^[A-Za-z0-9]{10,40}$/.test(id)) throw new HttpError(400, 'Invalid report');
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return json({ ok: false, reason: 'not configured' });
  if (notifiedReport.has(id)) return json({ ok: true, duplicate: true });

  const res = await fetch('https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID + '/databases/(default)/documents/reports/' + id, { headers: { Authorization: 'Bearer ' + user.token } });
  if (res.status !== 200) throw new HttpError(404, 'Report not found');
  const f = (await res.json()).fields || {};
  const val = (k) => (f[k] && f[k].stringValue !== undefined ? f[k].stringValue : f[k] && f[k].integerValue !== undefined ? f[k].integerValue : '');
  if (String(val('email')).toLowerCase() !== user.email) throw new HttpError(403, 'Not allowed');

  const last = lastReport.get(user.email);
  if (last && Date.now() - last < 8000) throw new HttpError(429, 'Please wait a moment');

  const what = val('kind') === 'resource' ? 'File: ' + val('title') + (val('page') ? ', page ' + val('page') : '') : 'Test: ' + val('title') + ', question ' + val('questionNo');
  const text = 'Mistake report\n\n' + what + '\nFrom: ' + user.email + '\n\n' + String(val('message')).slice(0, 400) + '\n\nOpen Admin → Reports to fix it.';
  notifiedReport.set(id, Date.now()); trimMap(notifiedReport, 500);
  lastReport.set(user.email, Date.now()); trimMap(lastReport, 500);
  const ok = await tgSend(env, env.TELEGRAM_CHAT_ID, text, url.origin + '/admin.html', 'Open admin panel');
  if (!ok) { notifiedReport.delete(id); throw new HttpError(502, 'Could not send the alert'); }
  return json({ ok: true });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (isOn(env.COMING_SOON)) {
        const pv = await previewParam(env, url);
        if (pv) return pv;
        if (await hasPreview(request, env)) {            // you, previewing: the whole real website, never cached for others
          env = Object.assign({}, env, { COMING_SOON: '0' });
          request = new Request(request); request.__preview = true;
        } else {
          const hidden = soonRoute(request, env, url);
          if (hidden) return hidden;
        }
      }
      const pub = await handlePublic(request, env, url);
      if (pub) return pub;
    }
    try {
      if (url.pathname === '/api/file' && request.method === 'GET') return await handleGet(request, env, url);
      if (url.pathname === '/api/file' && request.method === 'DELETE') return await handleDelete(request, env, url);
      if (url.pathname === '/api/upload' && request.method === 'PUT') return await handleUpload(request, env, url);
      if (url.pathname === '/api/notify-payment' && request.method === 'POST') return await handleNotify(request, env, url);
      if (url.pathname === '/api/notify-report' && request.method === 'POST') return await handleNotifyReport(request, env, url);
      if (url.pathname === '/api/announce' && request.method === 'POST') return await handleAnnounce(request, env);
      if (url.pathname === '/api/report-problem' && request.method === 'POST') return await handleReportProblem(request, env);
      if (url.pathname === '/api/admin-health' && (request.method === 'GET' || request.method === 'POST')) return await handleAdminHealth(request, env, url);
      if (url.pathname === '/api/backup' && ['GET', 'POST', 'DELETE'].indexOf(request.method) > -1) return await handleBackup(request, env, url);
      if (url.pathname === '/api/telegram-links' && (request.method === 'POST' || request.method === 'DELETE')) return await handleTelegramLinks(request, env, url);
      if (url.pathname.startsWith('/api/')) throw new HttpError(404, 'Not found');
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, code: e.code }, e.status);
      console.error('Worker error', e);
      const note = tgAlert(env, 'worker:' + url.pathname + ':' + String(e && e.message).slice(0, 40), 'Server error on ' + request.method + ' ' + url.pathname + '\n' + String(e && e.message).slice(0, 150));
      if (ctx && ctx.waitUntil) ctx.waitUntil(note); else await note;
      return json({ error: 'Server error' }, 500);
    }
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runAnnouncements(env).catch(e => { console.error('Cron failed', e); return tgAlert(env, 'cron-announce', 'The scheduled announcements job failed: ' + String(e && e.message).slice(0, 150)); }));
    ctx.waitUntil(runHealth(env).catch(e => console.error('Health check failed', e)));
  }
};
