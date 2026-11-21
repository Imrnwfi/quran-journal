// Shared backend logic for Quran Note.
// Every handler takes a `store` with the Netlify Blobs API (get/setJSON/delete/list),
// so the same code runs on Netlify and in local tests.
import crypto from "node:crypto";

export const TOTAL_PAGES = 604;
export const DEFAULT_TZ = "Asia/Kuala_Lumpur";
const MAX_DOC_BYTES = 1_000_000;
const MIN_PIN = 6;
const MAX_FAILS = 10;
const FAIL_WINDOW_MS = 15 * 60 * 1000;

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });

/* ---------------- validation ---------------- */
const isIso = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
const isPage = (n) => Number.isInteger(n) && n >= 1 && n <= TOTAL_PAGES;

export function validEntry(e) {
  return !!e && typeof e.id === "string" && e.id.length <= 80 && isPage(e.page) && isIso(e.date) &&
    typeof e.ts === "number" && (e.from == null || isPage(e.from)) &&
    (e.note == null || (typeof e.note === "string" && e.note.length <= 2000)) &&
    (e.tag == null || (typeof e.tag === "string" && e.tag.length <= 60));
}
export function validKhatam(k) {
  return !!k && typeof k.id === "string" && k.id.length <= 80 && isIso(k.date) && typeof k.ts === "number" &&
    (k.note == null || (typeof k.note === "string" && k.note.length <= 500)) &&
    (k.letter == null || (typeof k.letter === "string" && k.letter.length <= 3000));
}
// Learning data synced for the owner: tajwid stats per rule and the quiz history.
export function cleanLearn(l) {
  if (!l || typeof l !== "object") return undefined;
  const tj = {};
  if (l.tj && typeof l.tj === "object") {
    for (const [k, v] of Object.entries(l.tj).slice(0, 40)) {
      if (!/^[a-z0-9_]{1,30}$/.test(k) || !v || typeof v !== "object") continue;
      const n = Math.min(1e5, Math.max(0, Math.floor(+v.n || 0))), r = Math.min(n, Math.max(0, Math.floor(+v.r || 0)));
      const h = Array.isArray(v.h) ? v.h.slice(-10).map((x) => (x ? 1 : 0)) : [];
      tj[k] = { n, r, h };
    }
  }
  const log = [];
  if (Array.isArray(l.log)) {
    for (const x of l.log.slice(0, 300)) {
      if (!x) continue;
      if (["asma", "kata", "sirah", "hadis"].includes(x.k)) {
        const ts = Math.floor(+x.ts), id = String(x.id || "");
        if (!(ts > 0) || !/^[a-z0-9_-]{1,30}$/.test(id)) continue;
        const it = { k: x.k, id, ts, ok: !!x.ok, pick: typeof x.pick === "string" && /^[a-z0-9_-]{1,30}$/.test(x.pick) ? x.pick : null };
        if (x.h) it.h = 1;
        log.push(it); continue;
      }
      if (!["surah", "tajwid", "makna"].includes(x.k)) continue;
      const s = Math.floor(+x.s), a = Math.floor(+x.a), ts = Math.floor(+x.ts);
      if (!(s >= 1 && s <= 114 && a >= 1 && a <= 286 && ts > 0)) continue;
      const it = { k: x.k, s, a, ts, ok: !!x.ok };
      if (x.h) it.h = 1;
      if (x.p != null) { const pg = Math.floor(+x.p); if (pg >= 1 && pg <= 604) it.p = pg; }
      if (typeof x.rule === "string" && /^[a-z0-9_]{1,30}$/.test(x.rule)) it.rule = x.rule;
      if (x.pick === null || x.pick === undefined) it.pick = null;
      else if (typeof x.pick === "number" && x.pick >= 1 && x.pick <= 114) it.pick = Math.floor(x.pick);
      else if (typeof x.pick === "string" && /^[a-z0-9_:]{1,30}$/.test(x.pick)) it.pick = x.pick;
      log.push(it);
    }
  }
  return { tj, log };
}
export function cleanName(v) { return String(v || "").replace(/[\u0000-\u001f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 30); }
export function cleanDoc(doc) {
  if (!doc || typeof doc !== "object") return null;
  const { entries, khatams } = doc;
  if (!Array.isArray(entries) || !entries.every(validEntry)) return null;
  if (!Array.isArray(khatams) || !khatams.every(validKhatam)) return null;
  const del = doc.deleted || {};
  const ids = (a) => (Array.isArray(a) ? a.filter((x) => typeof x === "string").slice(-5000) : []);
  const s = doc.settings || {};
  return {
    entries: entries.map(({ id, page, from, note, date, ts, tag }) => ({ id, page, from: from ?? null, note: note || "", date, ts, ...(tag ? { tag } : {}) })),
    khatams: khatams.map(({ id, date, note, ts, letter }) => ({ id, date, note: note || "", ts, ...(typeof letter === "string" ? { letter } : {}) })),
    deleted: { entries: ids(del.entries), khatams: ids(del.khatams) },
    settings: {
      targetDate: isIso(s.targetDate) ? s.targetDate : "",
      tz: typeof s.tz === "string" && s.tz.length < 64 ? s.tz : DEFAULT_TZ,
      reminderMode: s.reminderMode === "fixed" ? "fixed" : "smart",
      weeklyReport: s.weeklyReport !== false,
      name: cleanName(s.name),
    },
    ...(doc.learn !== undefined ? { learn: cleanLearn(doc.learn) } : {}),
  };
}

/* ---------------- auth ---------------- */
function scrypt(pin, salt) {
  return crypto.scryptSync(pin, Buffer.from(salt, "hex"), 32).toString("hex");
}
function tokenFor(auth) {
  return crypto.createHmac("sha256", Buffer.from(auth.secret, "hex")).update("owner-v1").digest("hex");
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
export async function isOwner(req, store) {
  const h = req.headers.get("authorization") || "";
  const m = h.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!m) return false;
  const auth = await store.get("auth", { type: "json" });
  return !!auth && safeEq(m[1], tokenFor(auth));
}

export async function handleAuth(req, store) {
  if (req.method === "GET") {
    const auth = await store.get("auth", { type: "json" });
    const ok = auth ? await isOwner(req, store) : false;
    return json({ hasOwner: !!auth, valid: ok });
  }
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let body;
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const pin = typeof body.pin === "string" ? body.pin : "";
  const auth = await store.get("auth", { type: "json" });

  if (body.mode === "claim") {
    if (auth) return json({ error: "already_claimed" }, 409);
    if (pin.length < MIN_PIN || pin.length > 64) return json({ error: "pin_too_short" }, 400);
    const salt = crypto.randomBytes(16).toString("hex");
    const created = { salt, hash: scrypt(pin, salt), secret: crypto.randomBytes(32).toString("hex"), createdAt: Date.now() };
    await store.setJSON("auth", created);
    return json({ token: tokenFor(created) });
  }

  if (!auth) return json({ error: "no_owner" }, 404);
  const now = Date.now();
  const fails = ((await store.get("auth-fails", { type: "json" })) || { times: [] }).times.filter((t) => now - t < FAIL_WINDOW_MS);
  if (fails.length >= MAX_FAILS) return json({ error: "too_many_attempts" }, 429);
  if (!safeEq(scrypt(pin, auth.salt), auth.hash)) {
    await store.setJSON("auth-fails", { times: [...fails, now] });
    return json({ error: "wrong_pin", left: MAX_FAILS - fails.length - 1 }, 401);
  }
  if (fails.length) await store.setJSON("auth-fails", { times: [] });
  return json({ token: tokenFor(auth) });
}

/* ---------------- journal ---------------- */
export async function handleJournal(req, store) {
  const current = (await store.get("journal", { type: "json" })) || null;
  if (req.method === "GET") {
    const auth = await store.get("auth", { type: "json" });
    let doc = current ? current.doc : null;
    // Khatam time-capsule letters are private: only the owner gets them.
    if (doc && !(await isOwner(req, store))) { const { learn, ...rest } = doc; doc = { ...rest, khatams: doc.khatams.map(({ letter, ...k }) => k) }; }
    return json({ doc, version: current ? current.version : 0, hasOwner: !!auth });
  }
  if (req.method !== "PUT") return json({ error: "method" }, 405);
  if (!(await isOwner(req, store))) return json({ error: "unauthorized" }, 401);
  const raw = await req.text();
  if (raw.length > MAX_DOC_BYTES) return json({ error: "too_large" }, 413);
  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: "bad_json" }, 400); }
  const version = current ? current.version : 0;
  if (body.baseVersion !== version) return json({ error: "conflict", doc: current ? current.doc : null, version }, 409);
  const doc = cleanDoc(body.doc);
  if (!doc) return json({ error: "invalid_doc" }, 400);
  // A client that never received a letter (older app, or fetched without the owner token) must not erase it.
  if (current && current.doc) {
    const prev = new Map(current.doc.khatams.map((k) => [k.id, k]));
    doc.khatams = doc.khatams.map((k) => (k.letter === undefined && prev.get(k.id)?.letter ? { ...k, letter: prev.get(k.id).letter } : k));
    if (doc.learn === undefined && current.doc.learn) doc.learn = current.doc.learn;
  }
  const next = { doc, version: version + 1, updatedAt: Date.now() };
  await store.setJSON("journal", next);
  return json({ version: next.version });
}

/* ---------------- push ---------------- */
export async function vapidKeys(store, webpush) {
  let keys = await store.get("vapid", { type: "json" });
  if (!keys) {
    keys = webpush.generateVAPIDKeys();
    await store.setJSON("vapid", keys);
  }
  return keys;
}
const subKey = (endpoint) => "subs/" + crypto.createHash("sha256").update(endpoint).digest("hex").slice(0, 40);

function validSub(s) {
  return !!s && typeof s.endpoint === "string" && /^https:\/\//.test(s.endpoint) && s.endpoint.length < 1000 &&
    s.keys && typeof s.keys.p256dh === "string" && typeof s.keys.auth === "string";
}

export async function sendToAll(store, webpush, payload) {
  const keys = await vapidKeys(store, webpush);
  webpush.setVapidDetails("mailto:noreply@quran-journal.app", keys.publicKey, keys.privateKey);
  const { blobs } = await store.list({ prefix: "subs/" });
  let sent = 0, removed = 0, failed = 0;
  for (const b of blobs) {
    const sub = await store.get(b.key, { type: "json" });
    if (!sub) continue;
    try {
      await webpush.sendNotification(sub, JSON.stringify(payload), { TTL: 6 * 3600, urgency: "normal" });
      sent++;
    } catch (err) {
      if (err && (err.statusCode === 404 || err.statusCode === 410)) { await store.delete(b.key); removed++; }
      else failed++;
    }
  }
  return { sent, removed, failed };
}

export async function handlePush(req, store, webpush) {
  if (req.method === "GET") {
    const keys = await vapidKeys(store, webpush);
    return json({ publicKey: keys.publicKey });
  }
  if (!(await isOwner(req, store))) return json({ error: "unauthorized" }, 401);
  let body;
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  if (req.method === "POST" && body.action === "test") {
    const r = await sendToAll(store, webpush, {
      title: "Quran Note", body: "Notifikasi berfungsi ✓ Peringatan akan dihantar jam 7 malam jika belum membaca.", url: "/",
    });
    return json(r);
  }
  if (req.method === "POST") {
    if (!validSub(body.subscription)) return json({ error: "invalid_subscription" }, 400);
    const { endpoint, keys } = body.subscription;
    await store.setJSON(subKey(endpoint), { endpoint, keys: { p256dh: keys.p256dh, auth: keys.auth } });
    return json({ ok: true });
  }
  if (req.method === "DELETE") {
    if (typeof body.endpoint !== "string") return json({ error: "invalid" }, 400);
    await store.delete(subKey(body.endpoint));
    return json({ ok: true });
  }
  return json({ error: "method" }, 405);
}

/* ---------------- daily reminder ---------------- */
export function localDate(date, tz) {
  // en-CA gives YYYY-MM-DD
  return new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(date);
}

export function localHour(date, tz) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(date);
  const h = Number(parts.find((p) => p.type === "hour").value), m = Number(parts.find((p) => p.type === "minute").value);
  return h + m / 60;
}
// "Smart" reminder hour: one hour after the owner's usual logging time (median of the last 30 same-day logs).
// Needs at least 5 such logs; otherwise null. Clamped to 8:00–22:00.
export function smartHour(entries, tz) {
  const samples = entries
    .filter((e) => typeof e.ts === "number" && !String(e.id || "").startsWith("seed-") && localDate(new Date(e.ts), tz) === e.date)
    .sort((a, b) => b.ts - a.ts).slice(0, 30)
    .map((e) => localHour(new Date(e.ts), tz))
    .sort((a, b) => a - b);
  if (samples.length < 5) return null;
  const median = samples[Math.floor(samples.length / 2)];
  return Math.min(22, Math.max(8, Math.floor(median) + 1));
}
export function reminderHour(doc) {
  const tz = doc.settings?.tz || DEFAULT_TZ;
  if (doc.settings?.reminderMode === "fixed") return 19;
  return smartHour(doc.entries, tz) ?? 19;
}

export async function runReminder(store, webpush, now = new Date()) {
  const current = await store.get("journal", { type: "json" });
  if (!current || !current.doc) return { skipped: "no_data" };
  const tz = current.doc.settings?.tz || DEFAULT_TZ;
  const today = localDate(now, tz);
  if (current.doc.entries.some((e) => e.date === today)) return { skipped: "already_read", today };
  const hour = reminderHour(current.doc);
  if (localHour(now, tz) < hour) return { skipped: "not_yet", today, hour };
  const log = (await store.get("reminder-log", { type: "json" })) || {};
  if (log.lastSent === today) return { skipped: "already_sent", today };
  const last = [...current.doc.entries].sort((a, b) => (a.date === b.date ? b.ts - a.ts : b.date.localeCompare(a.date)))[0];
  const next = last ? Math.min(last.page + 1, TOTAL_PAGES) : 1;
  const result = await sendToAll(store, webpush, {
    title: "Quran Note 🌙",
    body: `${current.doc.settings?.name ? `${current.doc.settings.name}, hari` : "Hari"} ini belum dicatat lagi. Sambung dari muka surat ${next} — sedikit pun tak apa.`,
    url: "/?action=log",
  });
  await store.setJSON("reminder-log", { lastSent: today, at: now.toISOString(), ...result });
  return { today, ...result };
}

/* ---------------- prayer times (JAKIM e-Solat) ---------------- */
const MONTHS = { jan: 1, feb: 2, mar: 3, mac: 3, apr: 4, may: 5, mei: 5, jun: 6, jul: 7, aug: 8, ogo: 8, ogos: 8, sep: 9, oct: 10, okt: 10, nov: 11, dec: 12, dis: 12 };
const pad = (n) => String(n).padStart(2, "0");
function esolatDate(s) {
  // "14-Nov-2026" (or Malay month abbreviations) -> "2026-11-14"; already-ISO passes through
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const m = String(s).match(/^(\d{1,2})-([A-Za-z]+)-(\d{4})$/);
  if (!m) return null;
  const mon = MONTHS[m[2].toLowerCase()] || MONTHS[m[2].toLowerCase().slice(0, 3)];
  return mon ? `${m[3]}-${pad(mon)}-${pad(m[1])}` : null;
}
const hm = (t) => { const m = String(t || "").match(/^(\d{1,2}):(\d{2})/); return m ? `${pad(m[1])}:${m[2]}` : null; };

export function parseEsolat(json) {
  const list = json && Array.isArray(json.prayerTime) ? json.prayerTime : null;
  if (!list || !list.length) return null;
  const days = list.map((d) => ({
    date: esolatDate(d.date), hijri: typeof d.hijri === "string" ? d.hijri : null,
    imsak: hm(d.imsak), fajr: hm(d.fajr), syuruk: hm(d.syuruk), dhuhr: hm(d.dhuhr), asr: hm(d.asr), maghrib: hm(d.maghrib), isha: hm(d.isha),
  })).filter((d) => d.date && d.fajr && d.maghrib && d.isha);
  return days.length ? days : null;
}
export function parseWaktuSolatApp(json) {
  // api.waktusolat.app v2 (mirror of JAKIM e-Solat data): unix timestamps per day
  if (!json || !Array.isArray(json.prayers) || !json.year) return null;
  const month = json.month_number || null;
  const t = (u) => (typeof u === "number" ? new Intl.DateTimeFormat("en-GB", { timeZone: DEFAULT_TZ, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(new Date(u * 1000)) : null);
  const days = json.prayers.map((p) => {
    const date = month && p.day ? `${json.year}-${pad(month)}-${pad(p.day)}` : (typeof p.fajr === "number" ? localDate(new Date(p.fajr * 1000), DEFAULT_TZ) : null);
    return { date, hijri: typeof p.hijri === "string" ? p.hijri : null, imsak: p.imsak ? t(p.imsak) : null, fajr: t(p.fajr), syuruk: t(p.syuruk), dhuhr: t(p.dhuhr), asr: t(p.asr), maghrib: t(p.maghrib), isha: t(p.isha) };
  }).filter((d) => d.date && d.fajr && d.maghrib && d.isha);
  return days.length ? days : null;
}

const CODE_ABC = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
// Simple per-device limit (by hashed IP) so codes can't be guessed in bulk.
const ipOf = (req) => (req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "anon").split(",")[0].trim().slice(0, 64);
export async function rateLimit(req, store, bucket, max, windowMs, now = Date.now()) {
  const key = `rl/${bucket}/${crypto.createHash("sha256").update(ipOf(req)).digest("hex").slice(0, 24)}`;
  let r = null;
  try { r = await store.get(key, { type: "json" }); } catch (e) {}
  if (!r || !(r.reset > now)) r = { n: 0, reset: now + windowMs };
  r.n++;
  await store.setJSON(key, r);
  return r.n > max ? json({ error: "rate_limited", retryAfter: Math.ceil((r.reset - now) / 1000) }, 429) : null;
}
export async function handleTransfer(req, store, now = Date.now()) {
  const url = new URL(req.url);
  const limited = req.method === "POST" ? await rateLimit(req, store, "xfer-make", 10, 3600e3, now) : await rateLimit(req, store, "xfer-get", 20, 3600e3, now);
  if (limited) return limited;
  if (req.method === "POST") {
    let body; try { body = await req.json(); } catch (e) { return json({ error: "bad_json" }, 400); }
    const data = body && body.data;
    const raw = JSON.stringify(data || null);
    if (!data || !Array.isArray(data.entries) || raw.length > 400000) return json({ error: "invalid" }, 400);
    if (!data.entries.every(validEntry) || !(data.khatams || []).every(validKhatam)) return json({ error: "invalid" }, 400);
    let code = "";
    for (let i = 0; i < 8; i++) code += CODE_ABC[crypto.getRandomValues(new Uint8Array(1))[0] % CODE_ABC.length];
    const exp = now + 24 * 3600 * 1000;
    await store.setJSON(`transfer/${code}`, { data, exp });
    return json({ code, exp });
  }
  if (req.method === "GET") {
    const code = String(url.searchParams.get("code") || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (code.length !== 8) return json({ error: "bad_code" }, 400);
    const item = await store.get(`transfer/${code}`, { type: "json" });
    if (!item || item.exp < now) { if (item) await store.delete(`transfer/${code}`); return json({ error: "not_found" }, 404); }
    await store.delete(`transfer/${code}`); // one use only
    return json({ data: item.data });
  }
  return json({ error: "method" }, 405);
}

// Family challenge: a small group that sees each member's pages this week. Only names + weekly totals are shared.
const GROUP_MAX = 15;
const hashKey = (k) => crypto.createHash("sha256").update(String(k)).digest("hex");
const gName = (v, n = 30) => String(v || "").replace(/[\u0000-\u001f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, n);
const isWeek = (w) => typeof w === "string" && /^\d{4}-\d{2}-\d{2}$/.test(w);
function publicGroup(g) {
  return { name: g.name, goal: g.goal, created: g.created, members: g.members.map(({ key, ...m }) => m) };
}
export async function handleGroup(req, store, now = Date.now()) {
  const url = new URL(req.url);
  const norm = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (req.method === "GET") {
    const limited = await rateLimit(req, store, "group-get", 120, 3600e3, now);
    if (limited) return limited;
    const code = norm(url.searchParams.get("code"));
    if (code.length !== 6) return json({ error: "bad_code" }, 400);
    const g = await store.get(`group/${code}`, { type: "json" });
    return g ? json({ code, group: publicGroup(g) }) : json({ error: "not_found" }, 404);
  }
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let b; try { b = await req.json(); } catch (e) { return json({ error: "bad_json" }, 400); }
  const me = b && b.me;
  const id = me && /^[a-z0-9]{8,24}$/.test(me.id) ? me.id : null;
  const key = me && typeof me.key === "string" && me.key.length >= 16 && me.key.length <= 64 ? me.key : null;
  if (!id || !key) return json({ error: "bad_member" }, 400);
  const name = gName(me.name) || "—";
  const stats = (m) => {
    if (isWeek(b.week)) { m.week = b.week; m.pages = Math.max(0, Math.min(5000, Math.floor(+b.pages || 0))); m.days = Math.max(0, Math.min(7, Math.floor(+b.days || 0))); }
    m.name = name; m.ts = now; return m;
  };
  if (b.op === "create" || b.op === "join") {
    const limited = await rateLimit(req, store, "group-" + b.op, b.op === "create" ? 10 : 20, 3600e3, now);
    if (limited) return limited;
  }
  if (b.op === "create") {
    let code = "";
    for (let t = 0; t < 5; t++) {
      code = ""; for (let i = 0; i < 6; i++) code += CODE_ABC[crypto.getRandomValues(new Uint8Array(1))[0] % CODE_ABC.length];
      if (!(await store.get(`group/${code}`, { type: "json" }))) break;
    }
    const g = { name: gName(b.name, 40) || "Keluarga", goal: Math.max(0, Math.min(5000, Math.floor(+b.goal || 0))), created: now, members: [stats({ id, key: hashKey(key) })] };
    await store.setJSON(`group/${code}`, g);
    return json({ code, group: publicGroup(g) });
  }
  const code = norm(b.code);
  if (code.length !== 6) return json({ error: "bad_code" }, 400);
  const g = await store.get(`group/${code}`, { type: "json" });
  if (!g) return json({ error: "not_found" }, 404);
  const i = g.members.findIndex((m) => m.id === id);
  const mine = i >= 0 && g.members[i].key === hashKey(key);
  if (i >= 0 && !mine) return json({ error: "forbidden" }, 403);
  if (b.op === "join" || b.op === "update") {
    if (i < 0) {
      if (b.op === "update") return json({ error: "not_member" }, 403);
      if (g.members.length >= GROUP_MAX) return json({ error: "full" }, 409);
      g.members.push(stats({ id, key: hashKey(key) }));
    } else stats(g.members[i]);
    if (b.goal !== undefined) g.goal = Math.max(0, Math.min(5000, Math.floor(+b.goal || 0)));
    if (b.name !== undefined && b.op === "update" && b.groupName) g.name = gName(b.groupName, 40) || g.name;
  } else if (b.op === "leave") {
    if (i >= 0) g.members.splice(i, 1);
    if (!g.members.length) { await store.delete(`group/${code}`); return json({ code, group: null }); }
  } else return json({ error: "op" }, 400);
  await store.setJSON(`group/${code}`, g);
  return json({ code, group: publicGroup(g) });
}

// Feedback from users (error in a text, suggestion, problem). Anyone can send; only the owner can read or delete.
const FB_KINDS = ["teks", "cadangan", "masalah", "lain"];
export async function handleFeedback(req, store, now = Date.now()) {
  const url = new URL(req.url);
  if (req.method === "POST") {
    const limited = await rateLimit(req, store, "feedback", 5, 3600e3, now);
    if (limited) return limited;
    let b; try { b = await req.json(); } catch (e) { return json({ error: "bad_json" }, 400); }
    const clip = (v, n) => String(v || "").replace(/[\u0000-\u0008\u000b-\u001f<>]/g, "").trim().slice(0, n);
    const msg = clip(b && b.msg, 1000);
    if (!b || !FB_KINDS.includes(b.kind) || msg.length < 3) return json({ error: "invalid" }, 400);
    const item = { id: now.toString(36) + crypto.randomBytes(3).toString("hex"), ts: now, kind: b.kind, msg, name: clip(b.name, 40), ctx: clip(b.ctx, 80), ver: clip(b.ver, 12), lang: b.lang === "en" ? "en" : "ms" };
    const all = (await store.get("feedback/all", { type: "json" })) || [];
    await store.setJSON("feedback/all", [item, ...all].slice(0, 300));
    return json({ ok: true });
  }
  if (!(await isOwner(req, store))) return json({ error: "forbidden" }, 403);
  const all = (await store.get("feedback/all", { type: "json" })) || [];
  if (req.method === "GET") return json({ items: all });
  if (req.method === "DELETE") {
    const id = String(url.searchParams.get("id") || "");
    const left = id === "all" ? [] : all.filter((x) => x.id !== id);
    await store.setJSON("feedback/all", left);
    return json({ items: left });
  }
  return json({ error: "method" }, 405);
}

/* ---------------- personal accounts (passkey) ----------------
   Anyone can keep their own journal in the cloud, signed in with a passkey (fingerprint / Face ID).
   acct/u/<uid> user · acct/c/<credId> → uid · acct/r/<hash(recovery)> → uid · acct/s/<hash(token)> session · acct/d/<uid> journal */
const sha = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");
const ACCT_SESSION_DAYS = 400;
function recoveryCode() {
  let c = ""; for (let i = 0; i < 16; i++) c += CODE_ABC[crypto.randomBytes(1)[0] % CODE_ABC.length];
  return c.match(/.{4}/g).join("-");
}
const normRecovery = (c) => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
async function newSession(store, user, now) {
  const token = crypto.randomBytes(32).toString("base64url"), h = sha(token);
  await store.setJSON(`acct/s/${h}`, { uid: user.uid, exp: now + ACCT_SESSION_DAYS * 86400e3 });
  user.sess = [...(user.sess || []), h].slice(-20);
  return token;
}
async function acctSession(req, store, now = Date.now()) {
  const m = /^Bearer (.+)$/.exec(req.headers.get("authorization") || "");
  if (!m || m[1].length > 100) return null;
  const s = await store.get(`acct/s/${sha(m[1])}`, { type: "json" });
  if (!s || s.exp < now) return null;
  const user = await store.get(`acct/u/${s.uid}`, { type: "json" });
  return user ? { user, hash: sha(m[1]) } : null;
}
const acctName = (v) => String(v || "").replace(/[\u0000-\u001f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 40);
export async function handleAccount(req, store, wa, now = Date.now()) {
  if (req.method === "GET" || req.method === "PUT") {
    const ses = await acctSession(req, store, now);
    if (!ses) return json({ error: "unauthorized" }, 401);
    const uid = ses.user.uid, current = (await store.get(`acct/d/${uid}`, { type: "json" })) || null;
    if (req.method === "GET") return json({ doc: current ? current.doc : null, version: current ? current.version : 0, name: ses.user.name, passkeys: ses.user.creds.length });
    const raw = await req.text();
    if (raw.length > MAX_DOC_BYTES) return json({ error: "too_large" }, 413);
    let body; try { body = JSON.parse(raw); } catch { return json({ error: "bad_json" }, 400); }
    const version = current ? current.version : 0;
    if (body.baseVersion !== version) return json({ error: "conflict", doc: current ? current.doc : null, version }, 409);
    const doc = cleanDoc(body.doc);
    if (!doc) return json({ error: "invalid_doc" }, 400);
    if (current && current.doc && doc.learn === undefined && current.doc.learn) doc.learn = current.doc.learn;
    await store.setJSON(`acct/d/${uid}`, { doc, version: version + 1, updatedAt: now });
    return json({ version: version + 1 });
  }
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let body; try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const act = body && body.action;
  if (act === "logout" || act === "delete" || act === "status" || act === "rename") {
    const ses = await acctSession(req, store, now);
    if (!ses) return json({ error: "unauthorized" }, 401);
    const u = ses.user;
    if (act === "status") return json({ name: u.name, passkeys: u.creds.length, created: u.created });
    if (act === "rename") { u.name = acctName(body.name); await store.setJSON(`acct/u/${u.uid}`, u); return json({ ok: true, name: u.name }); }
    if (act === "logout") { await store.delete(`acct/s/${ses.hash}`); u.sess = (u.sess || []).filter((h) => h !== ses.hash); await store.setJSON(`acct/u/${u.uid}`, u); return json({ ok: true }); }
    // delete: the account, its passkeys, recovery code, sessions and cloud journal
    for (const c of u.creds) await store.delete(`acct/c/${sha(c.id)}`);
    for (const h of u.sess || []) await store.delete(`acct/s/${h}`);
    if (u.rec) await store.delete(`acct/r/${u.rec}`);
    await store.delete(`acct/d/${u.uid}`); await store.delete(`acct/u/${u.uid}`);
    return json({ ok: true, deleted: true });
  }
  if (act === "recover") {
    const limited = await rateLimit(req, store, "acct-recover", 10, 3600e3, now);
    if (limited) return limited;
    const code = normRecovery(body.code);
    if (code.length !== 16) return json({ error: "bad_code" }, 400);
    const map = await store.get(`acct/r/${sha(code)}`, { type: "json" });
    const user = map && (await store.get(`acct/u/${map.uid}`, { type: "json" }));
    if (!user) return json({ error: "not_found" }, 404);
    const token = await newSession(store, user, now);
    await store.setJSON(`acct/u/${user.uid}`, user);
    return json({ token, name: user.name, passkeys: user.creds.length });
  }
  const rp = rpFrom(req);
  if (!rp) return json({ error: "bad_origin" }, 400);
  if (act === "register-options") {
    const limited = await rateLimit(req, store, "acct-reg", 20, 3600e3, now);
    if (limited) return limited;
    const ses = await acctSession(req, store, now); // signed in: add another passkey to this account
    const uid = ses ? ses.user.uid : crypto.randomBytes(16).toString("hex");
    const name = ses ? ses.user.name : acctName(body.name);
    const options = await wa.generateRegistrationOptions({
      rpName: "Quran Note", rpID: rp.rpID, userName: name || "Jurnal Quran Note", userDisplayName: name || "Jurnal Quran Note",
      userID: new TextEncoder().encode(uid), attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      excludeCredentials: ses ? ses.user.creds.map((c) => ({ id: c.id, transports: c.transports })) : [],
    });
    const cid = await putChallenge(store, { type: "acct-reg", challenge: options.challenge, uid, name, add: !!ses });
    return json({ options, cid });
  }
  if (act === "register-verify") {
    const ch = await takeChallenge(store, body.cid, "acct-reg");
    if (!ch) return json({ error: "expired" }, 400);
    let v;
    try { v = await wa.verifyRegistrationResponse({ response: body.response, expectedChallenge: ch.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID, requireUserVerification: false }); }
    catch (e) { return json({ error: "verify_failed" }, 400); }
    if (!v.verified || !v.registrationInfo) return json({ error: "verify_failed" }, 400);
    const c = v.registrationInfo.credential;
    const cred = { id: c.id, publicKey: b64u(c.publicKey), counter: c.counter, transports: c.transports || [], createdAt: now, rpID: rp.rpID };
    let user = await store.get(`acct/u/${ch.uid}`, { type: "json" }), recovery = null;
    if (ch.add) {
      const ses = await acctSession(req, store, now);
      if (!ses || ses.user.uid !== ch.uid || !user) return json({ error: "unauthorized" }, 401);
      user.creds = [...user.creds.filter((x) => x.id !== cred.id), cred].slice(-10);
      await store.setJSON(`acct/c/${sha(cred.id)}`, { uid: user.uid });
      await store.setJSON(`acct/u/${user.uid}`, user);
      return json({ ok: true, passkeys: user.creds.length });
    }
    if (user) return json({ error: "exists" }, 409);
    recovery = recoveryCode();
    user = { uid: ch.uid, name: ch.name || "", created: now, creds: [cred], rec: sha(normRecovery(recovery)), sess: [] };
    await store.setJSON(`acct/r/${user.rec}`, { uid: user.uid });
    await store.setJSON(`acct/c/${sha(cred.id)}`, { uid: user.uid });
    const token = await newSession(store, user, now);
    await store.setJSON(`acct/u/${user.uid}`, user);
    return json({ token, recovery, name: user.name, passkeys: 1 });
  }
  if (act === "login-options") {
    const limited = await rateLimit(req, store, "acct-login", 60, 3600e3, now);
    if (limited) return limited;
    const options = await wa.generateAuthenticationOptions({ rpID: rp.rpID, userVerification: "preferred" });
    const cid = await putChallenge(store, { type: "acct-auth", challenge: options.challenge });
    return json({ options, cid });
  }
  if (act === "login-verify") {
    const ch = await takeChallenge(store, body.cid, "acct-auth");
    if (!ch) return json({ error: "expired" }, 400);
    const id = body.response && typeof body.response.id === "string" ? body.response.id : "";
    const map = id && (await store.get(`acct/c/${sha(id)}`, { type: "json" }));
    const user = map && (await store.get(`acct/u/${map.uid}`, { type: "json" }));
    const cred = user && user.creds.find((c) => c.id === id);
    if (!cred) return json({ error: "unknown_passkey" }, 401);
    let v;
    try {
      v = await wa.verifyAuthenticationResponse({ response: body.response, expectedChallenge: ch.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID, requireUserVerification: false,
        credential: { id: cred.id, publicKey: unb64u(cred.publicKey), counter: cred.counter, transports: cred.transports } });
    } catch (e) { return json({ error: "verify_failed" }, 401); }
    if (!v.verified) return json({ error: "verify_failed" }, 401);
    cred.counter = v.authenticationInfo.newCounter;
    const token = await newSession(store, user, now);
    await store.setJSON(`acct/u/${user.uid}`, user);
    return json({ token, name: user.name, passkeys: user.creds.length });
  }
  return json({ error: "action" }, 400);
}

export async function handleSolat(req, store, fetchImpl = fetch, now = new Date()) {
  const url = new URL(req.url);
  const zone = (url.searchParams.get("zone") || "").toUpperCase();
  if (!/^[A-Z]{3}\d{2}$/.test(zone)) return json({ error: "invalid_zone" }, 400);
  const today = localDate(now, DEFAULT_TZ);
  const key = `solat/${zone}/${today}`;
  const cached = await store.get(key, { type: "json" });
  if (cached) return json(cached, 200, { "cache-control": "public, max-age=1800" });

  const get = async (u) => {
    const res = await fetchImpl(u, { headers: { accept: "application/json", "user-agent": "QuranNote/1.0 (+prayer times)" }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error("http " + res.status);
    return res.json();
  };
  let days = null, source = null;
  try {
    days = parseEsolat(await get(`https://www.e-solat.gov.my/index.php?r=esolatApi/takwimsolat&period=week&zone=${zone}`));
    if (days) source = "JAKIM e-Solat (e-solat.gov.my)";
  } catch (e) {}
  if (!days) {
    try {
      days = parseWaktuSolatApp(await get(`https://api.waktusolat.app/v2/solat/${zone}`));
      if (days) source = "waktusolat.app (data JAKIM e-Solat)";
    } catch (e) {}
  }
  if (!days) return json({ error: "unavailable" }, 502);
  days = days.filter((d) => d.date >= today).slice(0, 8);
  const body = { zone, source, days, fetchedAt: now.toISOString() };
  await store.setJSON(key, body);
  return json(body, 200, { "cache-control": "public, max-age=1800" });
}

/* ---------------- weekly report (Sunday 9 pm) ---------------- */
// Pages each entry covers (same rule as the app): explicit from–to, otherwise continue from the previous entry; khatam starts a new round.
export function computeSpans(entries, khatams) {
  const ks = [...(khatams || [])].sort((a, b) => (a.date === b.date ? a.ts - b.ts : a.date.localeCompare(b.date)));
  const after = (e, k) => (e.date !== k.date ? e.date > k.date : e.ts > k.ts);
  const asc = [...entries].sort((a, b) => (a.date === b.date ? a.ts - b.ts : a.date.localeCompare(b.date)));
  const spans = {}; let ki = 0, prev = 0;
  for (const e of asc) {
    while (ki < ks.length && after(e, ks[ki])) { ki++; prev = 0; }
    let start = e.from ? e.from : prev + 1 <= e.page ? prev + 1 : e.page, end = e.page;
    if (start > end) [start, end] = [end, start];
    spans[e.id] = [start, end]; prev = Math.max(start, end);
  }
  return spans;
}
const isoAdd = (iso, n) => { const d = new Date(iso + "T12:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
export function weeklySummary(doc, today) {
  const spans = computeSpans(doc.entries, doc.khatams);
  const start = isoAdd(today, -6);
  let pages = 0; const days = new Set();
  for (const e of doc.entries) if (e.date >= start && e.date <= today) { const [a, b] = spans[e.id]; pages += b - a + 1; days.add(e.date); }
  const all = new Set(doc.entries.map((e) => e.date));
  let streak = 0, cur = all.has(today) ? today : isoAdd(today, -1);
  while (all.has(cur)) { streak++; cur = isoAdd(cur, -1); }
  return { pages, days: days.size, streak };
}
export async function runWeekly(store, webpush, now = new Date()) {
  const current = await store.get("journal", { type: "json" });
  if (!current || !current.doc) return { skipped: "no_data" };
  if (current.doc.settings?.weeklyReport === false) return { skipped: "off" };
  const tz = current.doc.settings?.tz || DEFAULT_TZ;
  const today = localDate(now, tz);
  const weekday = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short" }).format(now);
  if (weekday !== "Sun" || localHour(now, tz) < 21) return { skipped: "not_time" };
  const log = (await store.get("weekly-log", { type: "json" })) || {};
  if (log.lastSent === today) return { skipped: "already_sent" };
  const w = weeklySummary(current.doc, today);
  const who = current.doc.settings?.name ? `${current.doc.settings.name}, minggu` : "Minggu";
  const body = w.pages > 0
    ? `${who} ini: ${w.pages} muka surat · ${w.days}/7 hari membaca${w.streak > 1 ? ` · streak ${w.streak} hari 🔥` : ""}. Teruskan minggu depan, insya-Allah.`
    : "Minggu ini belum ada bacaan direkodkan. Jom mulakan semula — satu muka surat pun memadai 🤍";
  const result = await sendToAll(store, webpush, { title: "Laporan mingguan · Quran Note", body, url: "/#stats" });
  await store.setJSON("weekly-log", { lastSent: today, ...w, ...result });
  return { today, ...w, ...result };
}

/* ---------------- passkeys (WebAuthn) for the owner ---------------- */
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));
function rpFrom(req) {
  const origin = req.headers.get("origin") || "";
  let u; try { u = new URL(origin); } catch { return null; }
  const host = (req.headers.get("x-forwarded-host") || req.headers.get("host") || new URL(req.url).host || "").split(",")[0].trim();
  if (u.host !== host) return null; // only accept requests made from this site
  return { origin: u.origin, rpID: u.hostname };
}
async function putChallenge(store, data) {
  const cid = crypto.randomBytes(12).toString("hex");
  await store.setJSON(`pk-chal/${cid}`, { ...data, exp: Date.now() + 5 * 60 * 1000 });
  return cid;
}
async function takeChallenge(store, cid, type) {
  if (typeof cid !== "string" || !/^[a-f0-9]{24}$/.test(cid)) return null;
  const c = await store.get(`pk-chal/${cid}`, { type: "json" });
  await store.delete(`pk-chal/${cid}`);
  return c && c.type === type && c.exp > Date.now() ? c : null;
}

export async function handlePasskey(req, store, wa) {
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const rp = rpFrom(req);
  if (!rp) return json({ error: "bad_origin" }, 400);
  let body; try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const creds = (await store.get("passkeys", { type: "json" })) || [];
  const auth = await store.get("auth", { type: "json" });

  if (body.action === "status") return json({ count: creds.length });

  if (body.action === "register-options" || body.action === "register-verify" || body.action === "remove-all") {
    if (!(await isOwner(req, store))) return json({ error: "unauthorized" }, 401);
  }
  if (body.action === "register-options") {
    const options = await wa.generateRegistrationOptions({
      rpName: "Quran Note", rpID: rp.rpID, userName: "pemilik", userDisplayName: "Pemilik Quran Note",
      userID: new TextEncoder().encode("quran-note-owner"), attestationType: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      excludeCredentials: creds.map((c) => ({ id: c.id, transports: c.transports })),
    });
    const cid = await putChallenge(store, { type: "reg", challenge: options.challenge });
    return json({ options, cid });
  }
  if (body.action === "register-verify") {
    const ch = await takeChallenge(store, body.cid, "reg");
    if (!ch) return json({ error: "expired" }, 400);
    let v;
    try { v = await wa.verifyRegistrationResponse({ response: body.response, expectedChallenge: ch.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID, requireUserVerification: false }); }
    catch (e) { return json({ error: "verify_failed" }, 400); }
    if (!v.verified || !v.registrationInfo) return json({ error: "verify_failed" }, 400);
    const c = v.registrationInfo.credential;
    const entry = { id: c.id, publicKey: b64u(c.publicKey), counter: c.counter, transports: c.transports || [], createdAt: Date.now(), rpID: rp.rpID };
    await store.setJSON("passkeys", [...creds.filter((x) => x.id !== c.id), entry].slice(-10));
    return json({ ok: true, count: Math.min(creds.length + 1, 10) });
  }
  if (body.action === "remove-all") {
    await store.setJSON("passkeys", []);
    return json({ ok: true, count: 0 });
  }
  if (body.action === "login-options") {
    if (!auth) return json({ error: "no_owner" }, 404);
    const mine = creds.filter((c) => c.rpID === rp.rpID);
    if (!mine.length) return json({ error: "no_passkey" }, 404);
    const options = await wa.generateAuthenticationOptions({ rpID: rp.rpID, userVerification: "preferred", allowCredentials: mine.map((c) => ({ id: c.id, transports: c.transports })) });
    const cid = await putChallenge(store, { type: "auth", challenge: options.challenge });
    return json({ options, cid });
  }
  if (body.action === "login-verify") {
    if (!auth) return json({ error: "no_owner" }, 404);
    const ch = await takeChallenge(store, body.cid, "auth");
    if (!ch) return json({ error: "expired" }, 400);
    const cred = creds.find((c) => body.response && c.id === body.response.id);
    if (!cred) return json({ error: "unknown_passkey" }, 401);
    let v;
    try {
      v = await wa.verifyAuthenticationResponse({ response: body.response, expectedChallenge: ch.challenge, expectedOrigin: rp.origin, expectedRPID: rp.rpID, requireUserVerification: false,
        credential: { id: cred.id, publicKey: unb64u(cred.publicKey), counter: cred.counter, transports: cred.transports } });
    } catch (e) { return json({ error: "verify_failed" }, 401); }
    if (!v.verified) return json({ error: "verify_failed" }, 401);
    cred.counter = v.authenticationInfo.newCounter;
    await store.setJSON("passkeys", creds);
    return json({ token: tokenFor(auth) });
  }
  return json({ error: "unknown_action" }, 400);
}
