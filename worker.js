// PPTNEETPGHUB — private file gateway (Cloudflare Worker + R2)
//
//   GET    /api/file?key=...      members + admin: stream a private file
//   PUT    /api/upload?subject=&name=   admin only: upload a file, returns { key }
//   DELETE /api/file?key=...      admin only: delete a file
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

async function handleDelete(request, env, url) {
  const user = await requireUser(request, env);
  if (!user.isAdmin) throw new HttpError(403, 'Admin only');
  const key = cleanKey(url.searchParams.get('key'));
  await env.FILES.delete(key);
  return json({ deleted: key });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/api/file' && request.method === 'GET') return await handleGet(request, env, url);
      if (url.pathname === '/api/file' && request.method === 'DELETE') return await handleDelete(request, env, url);
      if (url.pathname === '/api/upload' && request.method === 'PUT') return await handleUpload(request, env, url);
      if (url.pathname.startsWith('/api/')) throw new HttpError(404, 'Not found');
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error('Worker error', e);
      return json({ error: 'Server error' }, 500);
    }
    return env.ASSETS.fetch(request);
  }
};
