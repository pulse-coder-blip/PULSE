// Pulse live: tiny WHOOP OAuth + API proxy. Node 18+, no dependencies.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
try { fs.readFileSync('.env', 'utf8').split('\n').forEach(l => { const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/); if (m) process.env[m[1]] = m[2]; }); } catch {}
const { WHOOP_CLIENT_ID: ID, WHOOP_CLIENT_SECRET: SECRET, PORT = 3000 } = process.env;
const REDIRECT = process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`;
const AUTH = 'https://api.prod.whoop.com/oauth/oauth2/auth', TOKEN = 'https://api.prod.whoop.com/oauth/oauth2/token';
const API = 'https://api.prod.whoop.com/developer/v2';
const SCOPE = 'offline read:recovery read:cycles read:sleep read:profile';
const TOKEN_FILE = path.join(__dirname, 'tokens.json');
let tokens = null, state = null, cache = { at: 0, rows: [] };
try { tokens = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')); } catch {}

async function tokenCall(params) {
  const r = await fetch(TOKEN, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: ID, client_secret: SECRET, ...params }) });
  if (!r.ok) throw new Error('Token error ' + r.status + ' ' + await r.text());
  const t = await r.json();
  tokens = { access: t.access_token, refresh: t.refresh_token || tokens?.refresh, exp: Date.now() + (t.expires_in - 60) * 1000 };
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens), { mode: 0o600 });
}
async function accessToken() {
  if (!tokens) return null;
  if (Date.now() > tokens.exp) await tokenCall({ grant_type: 'refresh_token', refresh_token: tokens.refresh, scope: 'offline' });
  return tokens.access;
}
async function getAll(endpoint, pages = 3) {
  const out = []; let next = null;
  for (let i = 0; i < pages; i++) {
    const u = new URL(API + endpoint); u.searchParams.set('limit', '25'); if (next) u.searchParams.set('nextToken', next);
    const r = await fetch(u, { headers: { Authorization: 'Bearer ' + await accessToken() } });
    if (r.status === 429) break;
    if (!r.ok) throw new Error(endpoint + ' ' + r.status);
    const j = await r.json(); out.push(...(j.records || [])); next = j.next_token; if (!next) break;
  }
  return out;
}
const min = ms => ms == null ? null : ms / 60000;
async function buildRows() {
  if (Date.now() - cache.at < 5 * 60 * 1000) return cache.rows;
  const [cycles, recs, sleeps] = await Promise.all([getAll('/cycle'), getAll('/recovery'), getAll('/activity/sleep')]);
  const cyc = Object.fromEntries(cycles.map(c => [c.id, c])), slp = Object.fromEntries(sleeps.map(s => [s.id, s]));
  const rows = recs.filter(r => r.score).map(r => {
    const c = cyc[r.cycle_id], s = slp[r.sleep_id], ss = s?.score?.stage_summary || {}, sn = s?.score?.sleep_needed || {};
    const light = min(ss.total_light_sleep_time_milli), deep = min(ss.total_slow_wave_sleep_time_milli), rem = min(ss.total_rem_sleep_time_milli);
    return {
      date: (s?.end || c?.start || r.created_at || '').slice(0, 10),
      rec: r.score.recovery_score, rhr: r.score.resting_heart_rate, hrv: r.score.hrv_rmssd_milli,
      spo2: r.score.spo2_percentage, temp: r.score.skin_temp_celsius,
      strain: c?.score?.strain ?? null, cal: c?.score?.kilojoule != null ? c.score.kilojoule / 4.184 : null,
      perf: s?.score?.sleep_performance_percentage ?? null, eff: s?.score?.sleep_efficiency_percentage ?? null,
      cons: s?.score?.sleep_consistency_percentage ?? null, resp: s?.score?.respiratory_rate ?? null,
      light, deep, rem, awake: min(ss.total_awake_time_milli),
      asleep: light != null ? light + deep + rem : null, debt: min(sn.need_from_sleep_debt_milli),
    };
  }).filter(r => r.date).sort((a, b) => a.date < b.date ? -1 : 1);
  cache = { at: Date.now(), rows }; return rows;
}
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  try {
    // Password gate: open https://your-app/?key=YOUR_PASSWORD once; a cookie remembers you.
    const PW = process.env.APP_PASSWORD;
    if (PW) {
      const good = crypto.createHash('sha256').update(PW).digest('hex');
      const ck = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith('pk='));
      const given = u.searchParams.get('key');
      if (given && crypto.createHash('sha256').update(given).digest('hex') === good) {
        res.writeHead(302, { 'Set-Cookie': 'pk=' + good + '; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000; Path=/', Location: '/' });
        return res.end();
      }
      if (!ck || ck.slice(3) !== good) { res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('Private. Add ?key=YOUR_PASSWORD to the address once.'); }
    }
    if (u.pathname === '/login') {
      state = crypto.randomBytes(8).toString('hex');
      const q = new URLSearchParams({ client_id: ID, redirect_uri: REDIRECT, response_type: 'code', scope: SCOPE, state });
      res.writeHead(302, { Location: AUTH + '?' + q }); return res.end();
    }
    if (u.pathname === '/callback') {
      if (u.searchParams.get('state') !== state) { res.writeHead(400); return res.end('Bad state'); }
      await tokenCall({ grant_type: 'authorization_code', code: u.searchParams.get('code'), redirect_uri: REDIRECT });
      res.writeHead(302, { Location: '/' }); return res.end();
    }
    if (u.pathname === '/api/metrics') {
      if (!tokens) { res.writeHead(401); return res.end('{}'); }
      res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(await buildRows()));
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
  } catch (e) { console.error(e); res.writeHead(500); res.end('Error: ' + e.message); }
}).listen(PORT, () => console.log('Pulse live on http://localhost:' + PORT));
