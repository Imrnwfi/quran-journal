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
    (e.note == null || (typeof e.note === "string" && e.note.length <= 2000));
}
export function validKhatam(k) {
  return !!k && typeof k.id === "string" && k.id.length <= 80 && isIso(k.date) && typeof k.ts === "number" &&
    (k.note == null || (typeof k.note === "string" && k.note.length <= 500));
}
export function cleanDoc(doc) {
  if (!doc || typeof doc !== "object") return null;
  const { entries, khatams } = doc;
  if (!Array.isArray(entries) || !entries.every(validEntry)) return null;
  if (!Array.isArray(khatams) || !khatams.every(validKhatam)) return null;
  const del = doc.deleted || {};
  const ids = (a) => (Array.isArray(a) ? a.filter((x) => typeof x === "string").slice(-5000) : []);
  const s = doc.settings || {};
  return {
    entries: entries.map(({ id, page, from, note, date, ts }) => ({ id, page, from: from ?? null, note: note || "", date, ts })),
    khatams: khatams.map(({ id, date, note, ts }) => ({ id, date, note: note || "", ts })),
    deleted: { entries: ids(del.entries), khatams: ids(del.khatams) },
    settings: {
      targetDate: isIso(s.targetDate) ? s.targetDate : "",
      tz: typeof s.tz === "string" && s.tz.length < 64 ? s.tz : DEFAULT_TZ,
    },
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
    return json({ doc: current ? current.doc : null, version: current ? current.version : 0, hasOwner: !!auth });
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

export async function runReminder(store, webpush, now = new Date()) {
  const current = await store.get("journal", { type: "json" });
  if (!current || !current.doc) return { skipped: "no_data" };
  const tz = current.doc.settings?.tz || DEFAULT_TZ;
  const today = localDate(now, tz);
  if (current.doc.entries.some((e) => e.date === today)) return { skipped: "already_read", today };
  const log = (await store.get("reminder-log", { type: "json" })) || {};
  if (log.lastSent === today) return { skipped: "already_sent", today };
  const last = [...current.doc.entries].sort((a, b) => (a.date === b.date ? b.ts - a.ts : b.date.localeCompare(a.date)))[0];
  const next = last ? Math.min(last.page + 1, TOTAL_PAGES) : 1;
  const result = await sendToAll(store, webpush, {
    title: "Quran Note 🌙",
    body: `Hari ini belum dicatat lagi. Sambung dari muka surat ${next} — sedikit pun tak apa.`,
    url: "/",
  });
  await store.setJSON("reminder-log", { lastSent: today, at: now.toISOString(), ...result });
  return { today, ...result };
}
