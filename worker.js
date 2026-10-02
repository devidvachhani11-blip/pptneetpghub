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

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
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
const memberCache = new Map(); // email -> expiry ms (positive results only)

async function isMember(user, env) {
  const hit = memberCache.get(user.email);
  if (hit && hit > Date.now()) return true;
  const url = 'https://firestore.googleapis.com/v1/projects/' + env.PROJECT_ID +
    '/databases/(default)/documents/members/' + encodeURIComponent(user.email);
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + user.token } });
  if (res.status === 200) {
    memberCache.set(user.email, Date.now() + 60 * 1000); // revocation takes effect within a minute
    return true;
  }
  return false;
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
  if (!user.isAdmin && !(await isMember(user, env))) throw new HttpError(403, 'Premium members only');

  const key = cleanKey(url.searchParams.get('key'));
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
const NEWS_CATEGORIES = ['NBEMS', 'MCC', 'State counselling', 'INICET', 'Seat matrix', 'Exam notice', 'Other'];
const COUNSELLING_CATS = ['MCC', 'State counselling', 'Seat matrix'];
const FRESH_SECONDS = 120;

function h(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function siteOf(env, url) { return String(env.SITE_URL || url.origin).replace(/\/$/, ''); }

function fsEq(field, value) {
  return { fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: typeof value === 'boolean' ? { booleanValue: value } : { stringValue: value } } };
}
function decodeNews(doc) {
  const f = doc.fields || {};
  const s = (k) => (f[k] && f[k].stringValue !== undefined ? f[k].stringValue : '');
  const t = (k) => (f[k] && f[k].timestampValue ? f[k].timestampValue : '');
  const date = s('date');
  return {
    id: doc.name.split('/').pop(), title: s('title'), slug: s('slug'), type: s('type') || 'update',
    category: s('category') || 'Other', summary: s('summary'), body: s('body'),
    sourceUrl: s('sourceUrl'), sourceName: s('sourceName'), date,
    pinned: !!(f.pinned && f.pinned.booleanValue),
    updatedAt: t('updatedAt') || t('createdAt') || (date ? date + 'T00:00:00Z' : '')
  };
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
.brand{font-weight:800;color:#fff;text-decoration:none;font-size:16px}.brand i{font-style:normal;color:#D4AF55;margin:0 4px}
nav.m{display:flex;gap:18px;align-items:center}nav.m a{color:#B4C0D6;text-decoration:none;font-size:14px;font-weight:500}nav.m a:hover{color:#fff}
.btn{display:inline-block;background:linear-gradient(135deg,#C9A24B,#EACF85);color:#0A1830!important;font-weight:700;text-decoration:none;border-radius:20px;padding:8px 16px;font-size:13px}
main{max-width:760px;margin:0 auto;padding:26px 18px 70px}.crumbs{font-size:12.5px;color:#6E7A8A;margin-bottom:14px}.crumbs a{color:#6E7A8A}
h1{font-size:clamp(26px,5vw,36px);line-height:1.18;color:#0A1830;margin:6px 0 10px;letter-spacing:-.3px}h2{font-size:20px;color:#0A1830;margin:26px 0 6px}
.pill{display:inline-block;background:#E8EEF9;color:#27508F;font-size:12px;font-weight:700;border-radius:10px;padding:3px 10px;margin-right:6px}.pill.g{background:#FFF8E8;color:#8A6A1A}
.meta{font-size:13px;color:#6E7A8A}.lead{font-size:16.5px;color:#3B4656;margin:10px 0 4px}.body p,.body li{font-size:16px}.body ul{padding-left:22px}
.src{background:#fff;border:1px solid #E3DCC8;border-left:4px solid #0F8F83;border-radius:12px;padding:12px 14px;margin:22px 0;font-size:14px}
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
@media(max-width:560px){nav.m a.hide{display:none}details.menu{display:block}.brand i,.brand .pr{display:none}nav.m{gap:10px}header.top .in{padding:12px 14px}}`;

function shell(site, o) {
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
    '<header class="top"><div class="in"><a class="brand" href="/">PPTNEETPGHUB<i>&middot;</i><span class="pr">Premium</span></a><nav class="m"><a class="hide" href="/news">News</a><a class="hide" href="/counselling">Counselling</a><a class="btn" href="/#join">Go Premium</a>' +
      '<details class="menu"><summary aria-label="Menu"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></summary><div class="panel">' +
      '<a href="/">Home</a><a href="/#features">What you get</a><a href="/#pricing">Pricing</a><a href="/news">News</a><a href="/counselling">Counselling</a><a href="/#faq">FAQ</a><hr><a href="/" style="color:#D4AF55;font-weight:700">Member sign in</a></div></details></nav></div></header>' +
    '<main>' + o.body + '</main>' +
    '<footer><div><a href="/">Home</a><a href="/news">News</a><a href="/counselling">Counselling</a><a href="/#pricing">Pricing</a></div><p>Summaries of official notices. Always confirm dates and rules on the official website before acting.</p></footer><script>document.addEventListener("click",function(e){var d=document.querySelector("details.menu");if(d&&d.open&&!d.contains(e.target))d.open=false;});</script></body></html>';
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
function itemCard(n) {
  return '<a class="item" href="/news/' + h(n.slug) + '"><span class="pill' + (n.type === 'guide' ? ' g' : '') + '">' + h(n.type === 'guide' ? 'Guide' : n.category) + '</span><span class="meta">' + h(niceDate(n.date)) + '</span><b>' + h(n.title) + '</b><span class="s">' + h(clip(n.summary, 170)) + '</span></a>';
}
function orgLd(site) { return { '@type': 'Organization', name: 'PPTNEETPGHUB', url: site }; }
function crumbLd(site, trail) {
  return { '@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: trail.map((t, i) => ({ '@type': 'ListItem', position: i + 1, name: t[0], item: site + t[1] })) };
}

async function newsListPage(env, url) {
  const site = siteOf(env, url);
  const cat = url.searchParams.get('c') || '';
  const all = await allPublished(env);
  const list = all.filter(n => n.slug !== 'counselling' && (!cat || n.category === cat));
  const pinned = list.filter(n => n.pinned && !cat), rest = list.filter(n => !(n.pinned && !cat));
  const chips = '<div class="chips"><a href="/news"' + (!cat ? ' class="on"' : '') + '>All</a>' +
    NEWS_CATEGORIES.map(c => '<a href="/news?c=' + encodeURIComponent(c) + '"' + (cat === c ? ' class="on"' : '') + '>' + h(c) + '</a>').join('') + '</div>';
  const body = '<div class="crumbs"><a href="/">Home</a> › News</div><h1>NEET PG and INICET updates</h1>' +
    '<p class="lead">Counselling, seat matrix, exam notices and guides, summarised from official sources.</p>' + chips +
    (list.length ? pinned.concat(rest).map(itemCard).join('') : '<p>No updates here yet. Check back soon.</p>') + ctaBox();
  return htmlResponse(shell(site, {
    title: 'NEET PG & INICET news, counselling updates | PPTNEETPGHUB',
    desc: 'Latest NEET PG and INICET updates: MCC and state counselling, seat matrix, NBEMS notices and exam guides, with links to the official sources.',
    path: '/news', noindex: !!cat, body,
    ld: [crumbLd(site, [['Home', '/'], ['News', '/news']])]
  }));
}

async function articlePage(env, url, slug) {
  const site = siteOf(env, url);
  const rows = await fsNews(env, [fsEq('slug', slug), fsEq('published', true)]);
  const n = rows[0];
  if (!n) return notFoundPage(site);
  if (n.slug === 'counselling') return Response.redirect(site + '/counselling', 301);
  const all = await allPublished(env);
  const related = all.filter(x => x.id !== n.id && x.slug !== 'counselling' && x.category === n.category).slice(0, 4);
  const path = '/news/' + n.slug;
  const updated = n.updatedAt ? n.updatedAt.slice(0, 10) : n.date;
  const body = '<div class="crumbs"><a href="/">Home</a> › <a href="/news">News</a> › ' + h(clip(n.title, 50)) + '</div>' +
    '<span class="pill' + (n.type === 'guide' ? ' g' : '') + '">' + h(n.type === 'guide' ? 'Guide' : n.category) + '</span>' +
    '<span class="meta">' + (n.date ? 'Date: ' + h(niceDate(n.date)) : '') + (updated && updated !== n.date ? ' · Last updated: ' + h(niceDate(updated)) : '') + '</span>' +
    '<h1>' + h(n.title) + '</h1><p class="lead">' + h(n.summary) + '</p><div class="body">' + renderBody(n.body) + '</div>' +
    (/^https?:\/\//.test(n.sourceUrl) ? '<div class="src"><b>Official source:</b> <a href="' + h(n.sourceUrl) + '" target="_blank" rel="noopener">' + h(n.sourceName || n.sourceUrl) + '</a><br><span class="meta">Always confirm on the official website.</span></div>' : '') +
    ctaBox() + (related.length ? '<h2>More ' + h(n.category) + ' updates</h2>' + related.map(itemCard).join('') : '');
  return htmlResponse(shell(site, {
    title: clip(n.title, 60) + ' | PPTNEETPGHUB', desc: clip(n.summary || n.title, 160), path, ogType: 'article', body,
    ld: [{ '@context': 'https://schema.org', '@type': n.type === 'guide' ? 'Article' : 'NewsArticle', headline: clip(n.title, 110), description: clip(n.summary, 200),
      datePublished: n.date || undefined, dateModified: updated || n.date || undefined, mainEntityOfPage: site + path, author: orgLd(site), publisher: orgLd(site) },
      crumbLd(site, [['Home', '/'], ['News', '/news'], [clip(n.title, 60), path]])]
  }));
}

async function counsellingPage(env, url) {
  const site = siteOf(env, url);
  const all = await allPublished(env);
  const guide = all.find(n => n.slug === 'counselling');
  const latest = all.filter(n => n.slug !== 'counselling' && COUNSELLING_CATS.indexOf(n.category) > -1).slice(0, 8);
  const updated = guide && guide.updatedAt ? guide.updatedAt.slice(0, 10) : '';
  const body = '<div class="crumbs"><a href="/">Home</a> › Counselling</div>' +
    '<h1>' + h(guide ? guide.title : 'NEET PG counselling: rounds, seat matrix and updates') + '</h1>' +
    (guide ? '<p class="meta">' + (updated ? 'Last updated: ' + h(niceDate(updated)) : '') + '</p><p class="lead">' + h(guide.summary) + '</p><div class="body">' + renderBody(guide.body) + '</div>' +
      (/^https?:\/\//.test(guide.sourceUrl) ? '<div class="src"><b>Official source:</b> <a href="' + h(guide.sourceUrl) + '" target="_blank" rel="noopener">' + h(guide.sourceName || guide.sourceUrl) + '</a></div>' : '')
      : '<p class="lead">Counselling dates, rounds and seat matrix updates are listed below as soon as they are published.</p>') +
    '<h2>Latest counselling updates</h2>' + (latest.length ? latest.map(itemCard).join('') : '<p>No counselling updates yet. Check back soon.</p>') +
    '<p><a href="/news">See all updates →</a></p>' + ctaBox();
  return htmlResponse(shell(site, {
    title: clip(guide ? guide.title : 'NEET PG counselling: rounds, seat matrix, updates', 60) + ' | PPTNEETPGHUB',
    desc: clip(guide && guide.summary ? guide.summary : 'NEET PG counselling guide: MCC and state counselling rounds, seat matrix, documents and the latest updates with official links.', 160),
    path: '/counselling', body, ld: [crumbLd(site, [['Home', '/'], ['Counselling', '/counselling']])]
  }));
}

async function sitemapXml(env, url) {
  const site = siteOf(env, url);
  const all = await allPublished(env);
  const rows = [{ loc: '/', mod: '' }, { loc: '/news', mod: all.length ? (all[0].updatedAt || '').slice(0, 10) : '' }];
  const g = all.find(n => n.slug === 'counselling');
  rows.push({ loc: '/counselling', mod: g ? (g.updatedAt || '').slice(0, 10) : '' });
  all.filter(n => n.slug !== 'counselling').forEach(n => rows.push({ loc: '/news/' + n.slug, mod: (n.updatedAt || n.date || '').slice(0, 10) }));
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
  const all = (await allPublished(env)).filter(x => x.slug !== 'counselling').slice(0, n);
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
    if (p === '/news') return await cachedPage(request, FRESH_SECONDS, () => newsListPage(env, url));
    if (p === '/counselling') return await cachedPage(request, FRESH_SECONDS, () => counsellingPage(env, url));
    const m = /^\/news\/([a-z0-9-]{3,80})$/.exec(p);
    if (m) return await cachedPage(request, FRESH_SECONDS, () => articlePage(env, url, m[1]));
    if (p.startsWith('/news/')) return notFoundPage(site);
  } catch (e) {
    console.error('News page failed', e);
    return htmlResponse(shell(site, { title: 'Temporarily unavailable | PPTNEETPGHUB', desc: 'Please try again in a moment.', path: '/news', noindex: true,
      body: '<h1>Temporarily unavailable</h1><p class="lead">Updates could not be loaded just now. Please try again in a minute.</p><p><a href="/">Back to home</a></p>' }), 503);
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' || request.method === 'HEAD') {
      const pub = await handlePublic(request, env, url);
      if (pub) return pub;
    }
    try {
      if (url.pathname === '/api/file' && request.method === 'GET') return await handleGet(request, env, url);
      if (url.pathname === '/api/file' && request.method === 'DELETE') return await handleDelete(request, env, url);
      if (url.pathname === '/api/upload' && request.method === 'PUT') return await handleUpload(request, env, url);
      if (url.pathname === '/api/notify-payment' && request.method === 'POST') return await handleNotify(request, env, url);
      if (url.pathname.startsWith('/api/')) throw new HttpError(404, 'Not found');
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error('Worker error', e);
      return json({ error: 'Server error' }, 500);
    }
    return env.ASSETS.fetch(request);
  }
};
