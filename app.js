/* =============================================================================
   PRINTREADYART CLAIM ENGINE  —  first-test version.
   Bubble is the database; this script is the clock + rotation brain.
   -----------------------------------------------------------------------------
   Run (Development data -- note the version-test in the URL):
     npm i express
     $env:BUBBLE_BASE="https://YOURAPP.bubbleapps.io/version-test/api/1.1/obj"
     $env:BUBBLE_TOKEN="your-dev-token"
     node app.js

   WHAT THIS VERSION DOES: starts a clock on any order flagged use_new_system=yes
   with an empty claim_state, lets a vendor claim, rotates on expiry, escalates at
   the cap. WHAT IT DOESN'T DO YET: auto-sort new orders from the Team flag, and
   write Order_Event history rows. Those come next.
============================================================================= */

const express = require("express");
const path = require("path");

// ----------------------------- CONFIG ---------------------------------------
const BUBBLE_BASE  = process.env.BUBBLE_BASE  || "https://YOURAPP.bubbleapps.io/version-test/api/1.1/obj";
const BUBBLE_TOKEN = process.env.BUBBLE_TOKEN || "PASTE_DEV_TOKEN";
const PORT         = Number(process.env.PORT || 3000);
const CLAIM_WINDOW_MIN = Number(process.env.CLAIM_WINDOW_MIN || 15);
const HARD_CAP_MIN     = Number(process.env.HARD_CAP_MIN     || 120);
const SWEEP_SECONDS    = Number(process.env.SWEEP_SECONDS    || 30);
const AGING_MIN        = Number(process.env.AGING_MIN        || 60); // unclaimed longer than this = "aging" flag for dashboard
const REF_FIELD        = process.env.REF_FIELD || "Customer_PO#"; // order label to show (confirmed field name)

// Field names MUST match Bubble's API keys EXACTLY, including capitalization.
// These were confirmed from the raw order JSON (peek.js).
const F = {
  assignedArtist: "Assigned_Artist",   // capital A/A (was the undefined bug)
  claimState:     "claim_state",
  claimDeadline:  "claim_deadline",
  hardDeadline:   "hard_deadline",
  claimedAt:      "claimed_at",
  triedVendors:   "tried_vendors",
  rotationCount:  "rotation_count",
  lastAssigned:   "last_assigned_at",
  useNewSystem:   "use_new_system",
  separations:    "Separations",       // capital S; value is text "yes"/"no"
};

// Artist type field names.
const ART = {
  email:          "email",             // artist email field (confirmed: plain "email")
  maxConcurrent:  "max_concurrent_orders",
  isActive:       "is_active_vendor",
  capabilities:   "capabilities",
};
const CS = { unclaimed: "unclaimed", claimed: "claimed", review: "needs_review", completed: "completed", edit: "edit_requested" };

// use_new_system is a real yes/no field -> Bubble returns boolean true/false.
const YES = true;

function requiredCapsForOrder(o) {
  const caps = [];
  // Order type -> capability tag.
  const TYPE_CAP = { "Vector": "vector", "Digitizing": "digitizing", "Digital (DTF/DTG)": "digital_printing" };
  const t = TYPE_CAP[o.Order_Type];
  if (t) caps.push(t);
  // Sub-capabilities are SCOPED to their parent type (strict subset model):
  //   separations belongs only to Vector; ofm/pfx belong only to Digitizing.
  // This prevents nonsense requirements like [digitizing, separations].
  if (o.Order_Type === "Vector" && (o[F.separations] === "yes" || o[F.separations] === true)) caps.push("separations");
  if (o.Order_Type === "Digitizing") {
    if (o.OFM === "yes" || o.OFM === true) caps.push("ofm");
    if (o.PXF === "yes" || o.PXF === true) caps.push("pfx");
  }
  return caps;
}

// --------------------------- BUBBLE DATA API ---------------------------------
async function bubble(method, p, body) {
  const res = await fetch(`${BUBBLE_BASE}${p}`, {
    method,
    headers: { Authorization: `Bearer ${BUBBLE_TOKEN}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`Bubble ${method} ${p} -> ${res.status} ${await res.text()}`);
  return method === "GET" ? res.json() : null;
}
const getOrder   = (id) => bubble("GET", `/uploaded_image/${id}`).then(r => r.response);
const patchOrder = (id, fields) => bubble("PATCH", `/uploaded_image/${id}`, fields);

async function search(type, constraints) {
  const out = []; let cursor = 0;
  for (;;) {
    const q = `constraints=${encodeURIComponent(JSON.stringify(constraints))}&cursor=${cursor}&limit=100`;
    const { response } = await bubble("GET", `/${type}?${q}`);
    out.push(...response.results);
    if (response.remaining <= 0 || response.results.length === 0) return out;
    cursor += response.results.length;
  }
}

async function artistByEmail(email) {
  const rows = await search("artist", [{ key: ART.email, constraint_type: "equals", value: email }]);
  const a = rows[0];
  return a ? { email, maxConcurrent: Number(a[ART.maxConcurrent] || 0),
              capabilities: a[ART.capabilities] || [] } : null;
}
const activeVendors = () =>
  search("artist", [{ key: ART.isActive, constraint_type: "equals", value: YES }])
    .then(rows => rows.map(a => ({ email: a[ART.email], maxConcurrent: Number(a[ART.maxConcurrent] || 0),
                                   capabilities: a[ART.capabilities] || [] })));
async function eligibleVendors(order) {
  const need = requiredCapsForOrder(order);
  const all = await activeVendors();
  if (!need.length) return all; // unrecognized type: no capability to gate on
  // STRICT capability gating: only vendors who carry EVERY required capability.
  // No fallback to all-active -- an order no one is capable of waits for an admin
  // (surfaced on the dashboard as "no eligible vendor") rather than leaking to
  // vendors who aren't set up for that work.
  return all.filter(v => need.every(c => (v.capabilities || []).map(x => String(x).toLowerCase()).includes(c)));
}
// A vendor's "load" against their cap = active claimed work PLUS open edit requests
// (edit requests are unpaid rework; counting them throttles new paid intake until edits
// are cleared). This single count feeds both tryClaim and rotation, so the rule is
// enforced consistently. Edit-request reads are fail-safe: if that table can't be read,
// we fall back to claimed-only rather than block all claiming.
async function countClaimed(email) {
  const claimed = await search("uploaded_image", [
    { key: F.assignedArtist, constraint_type: "equals", value: email },
    { key: F.claimState, constraint_type: "equals", value: CS.claimed }]);
  let openEdits = [];
  try {
    openEdits = await search("edit_request", [
      { key: "Assigned_Artist", constraint_type: "equals", value: email },
      { key: "Completed", constraint_type: "is_empty" }]);
  } catch (e) { console.warn("[countClaimed] edit_request count failed:", e.message); }
  return claimed.length + openEdits.length;
}

// ------------------------------ PER-ORDER LOCK -------------------------------
const chains = new Map();
function withLock(id, fn) {
  const prev = chains.get(id) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  chains.set(id, next.finally(() => { if (chains.get(id) === next) chains.delete(id); }));
  return next;
}

// ------------------------------ EVENT LOG ------------------------------------
// Writes one Order_Event row per transition. FAIL-SAFE: if logging errors,
// we warn but never throw -- an audit-log hiccup must not break a claim/rotation.
async function logEvent(orderId, email, eventType, note = "") {
  try {
    await bubble("POST", "/order_event", {
      order: orderId,            // link field: set by the linked thing's _id
      artist_email: email || "",
      event_type: eventType,
      note,
    });
  } catch (e) {
    console.warn(`[event-log warning] could not log ${eventType} for ${orderId}: ${e.message}`);
  }
}

// ------------------------------ CORE LOGIC -----------------------------------
function notifyVendor(email) { console.log(`[notify] ${email} has an order to claim`); }

async function startClock(orderId) {
  // SHARED POOL: an order simply enters the claimable pool -- unclaimed and
  // unassigned. Every active, under-cap vendor whose capabilities match can see
  // and claim it (first-claim-wins, enforced atomically in tryClaim under a lock).
  // We intentionally do NOT pre-stamp Assigned_Artist, so no single vendor "owns"
  // a waiting order and orders can't pile up on one person.
  await patchOrder(orderId, {
    [F.claimState]: CS.unclaimed,
    [F.assignedArtist]: "",
    [F.lastAssigned]: Date.now(),
  });
  const o = await getOrder(orderId);
  const eligible = await eligibleVendors(o);
  console.log(`[pool] order ${orderId} entered the shared claim pool -- ${eligible.length} eligible vendor(s)`);
  await logEvent(orderId, "", "entered_pool", `shared pool; ${eligible.length} eligible`);
  eligible.forEach(v => notifyVendor(v.email));
}

async function tryClaim(orderId, email) {
  const o = await getOrder(orderId);
  const st = o[F.claimState] || "";
  // Claimable only while still in the pool (blank or unclaimed). The per-order lock
  // around this call makes first-claim-wins atomic: a second claimer reads "claimed".
  if (st !== "" && st !== CS.unclaimed) return { ok: false, reason: "already_taken" };
  const a = await artistByEmail(email);
  if (!a) return { ok: false, reason: "no_artist_with_that_email" };
  // STRICT capability gate: the claimer must carry every capability the order needs.
  const need = requiredCapsForOrder(o);
  const caps = (a.capabilities || []).map(x => String(x).toLowerCase());
  if (!need.every(c => caps.includes(c)))
    return { ok: false, reason: "not_eligible_for_this_work" };
  if ((await countClaimed(email)) >= a.maxConcurrent)
    return { ok: false, reason: "at_limit_finish_open_work_first" };
  await patchOrder(orderId, { [F.claimState]: CS.claimed, [F.assignedArtist]: email, [F.claimedAt]: Date.now() });
  console.log(`[claimed] order ${orderId} by ${email} (from shared pool)`);
  await logEvent(orderId, email, "claimed", "from shared pool");
  return { ok: true };
}

// Admin push: force an order onto a vendor as instantly claimed, OVER their cap,
// no window, no rotation. This is how an aging/parked order gets resolved.
async function forceAssign(orderId, email) {
  const a = await artistByEmail(email);
  if (!a) return { ok: false, reason: "no_artist_with_that_email" };
  const open = await countClaimed(email);
  await patchOrder(orderId, {
    [F.claimState]: CS.claimed,
    [F.assignedArtist]: email,
    [F.claimedAt]: Date.now(),
  });
  console.log(`[force-assigned] order ${orderId} -> ${email} (now ${open + 1}/${a.maxConcurrent}${open + 1 > a.maxConcurrent ? ", OVER cap" : ""})`);
  await logEvent(orderId, email, "admin_force_assigned",
    `admin push; vendor now ${open + 1}/${a.maxConcurrent}`);
  return { ok: true, overCap: open + 1 > a.maxConcurrent };
}

async function escalate(id, why) {
  await patchOrder(id, { [F.claimState]: CS.review });
  console.log(`[escalated] order ${id} -- ${why}`);
  await logEvent(id, "", "escalated", why);
}

// Pick the next eligible active vendor who's under cap and not already tried.
// Returns the email, or null if nobody is available.
async function pickNextVendor(order, tried) {
  const eligible = await eligibleVendors(order);
  console.log(`   eligible vendors: [${eligible.map(v => v.email).join(", ")}] | tried: [${[...tried].join(", ")}]`);
  for (const v of eligible) {
    if (tried.has(v.email)) continue;
    const open = await countClaimed(v.email);
    if (open >= v.maxConcurrent) { console.log(`   skip ${v.email} (at cap ${open}/${v.maxConcurrent})`); continue; }
    return v.email;
  }
  return null;
}

async function rotateIfDue(o) {
  const now = Date.now();
  if (o[F.claimState] !== CS.unclaimed) return;
  if (now < new Date(o[F.claimDeadline]).getTime()) return;
  // No hard-cap parking and no zero-vendor escalation: orders rotate perpetually.
  // Aging is surfaced on the admin dashboard (/api/aging); admin pushes when ready.

  const eligible = await eligibleVendors(o);
  if (eligible.length === 0) {
    // Nobody eligible right now (off-hours, all inactive, capability gap).
    // Don't escalate -- just wait and retry; it stays in rotation.
    console.log(`[waiting] order ${o._id} -- no eligible vendor right now, retry in 5 min`);
    return patchOrder(o._id, { [F.claimDeadline]: now + 5 * 60000 });
  }

  const tried = new Set(o[F.triedVendors] || []);
  if (o[F.assignedArtist]) tried.add(o[F.assignedArtist]);

  const next = await pickNextVendor(o, tried);
  if (!next) {
    const allTried = eligible.every(v => tried.has(v.email));
    if (allTried) {
      // Full pass through every eligible vendor with no claim.
      // NEVER park -- start another pass. review_count is an aging signal only,
      // surfaced on the admin dashboard so a human can choose to push. The order
      // rotates perpetually until claimed or an admin force-assigns it.
      const passNum = Number(o.review_count || 0) + 1;
      console.log(`[re-rotating] order ${o._id} -- full pass ${passNum} done, starting another pass`);
      await logEvent(o._id, "", "full_pass_complete", `pass ${passNum}; re-entering rotation`);
      await patchOrder(o._id, {
        [F.triedVendors]: [],
        review_count: passNum,
        [F.claimDeadline]: now + CLAIM_WINDOW_MIN * 60000,
        [F.lastAssigned]: now,
      });
      return;
    }
    console.log(`[waiting] order ${o._id} -- all eligible vendors at cap, retry in 5 min`);
    return patchOrder(o._id, { [F.claimDeadline]: now + 5 * 60000 });
  }

  const newCount = Number(o[F.rotationCount] || 0) + 1;
  await patchOrder(o._id, {
    [F.assignedArtist]: next, [F.triedVendors]: [...tried],
    [F.claimDeadline]: now + CLAIM_WINDOW_MIN * 60000, [F.lastAssigned]: now,
    [F.rotationCount]: newCount,
  });
  console.log(`[rotated] order ${o._id} -> ${next}`);
  await logEvent(o._id, next, "rotated", `rotation #${newCount}, from ${o[F.assignedArtist] || "(none)"}`);
  notifyVendor(next);
}

async function sweep() {
  try {
    // 1) New flagged orders not yet started -> drop into the shared pool.
    const fresh = await search("uploaded_image", [
      { key: F.useNewSystem, constraint_type: "equals", value: YES },
      { key: F.claimState, constraint_type: "is_empty" },
    ]);
    for (const o of fresh) await withLock(o._id, () => startClock(o._id));
    // 2) Open orders just wait in the shared pool for any eligible vendor to claim.
    //    No rotation, no per-vendor window -- nothing to do but count them.
    const open = await search("uploaded_image", [{ key: F.claimState, constraint_type: "equals", value: CS.unclaimed }]);
    if (fresh.length || open.length) console.log(`[sweep] ${fresh.length} new -> pool, ${open.length} waiting in pool`);
  } catch (e) { console.error("[sweep error]", e.message); }
}

// -------------------------------- HTTP / PAGE --------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
const mapOrder = (o) => ({ id: o._id, ref: o[REF_FIELD] || o._id, deadline: o[F.claimDeadline] });

// ---- Shared-secret auth for admin endpoints --------------------------------
// Set ADMIN_SECRET as a Railway variable. Any caller (the Bubble admin page)
// must send it in the "x-admin-secret" header. Without a matching secret, the
// admin endpoints reject the request. If ADMIN_SECRET is unset, admin endpoints
// are DISABLED entirely (fail closed) rather than left open.
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
function requireAdmin(req, res, next) {
  if (!ADMIN_SECRET) return res.status(503).json({ error: "admin endpoints disabled: ADMIN_SECRET not set" });
  const sent = req.get("x-admin-secret") || "";
  // constant-time-ish compare
  if (sent.length !== ADMIN_SECRET.length || sent !== ADMIN_SECRET)
    return res.status(401).json({ error: "unauthorized" });
  next();
}

app.get("/api/my-orders", async (req, res) => {
  try {
    const email = String(req.query.email || "");
    const a = await artistByEmail(email);
    if (!a) return res.status(404).json({ error: "no artist with that email" });
    const unclaimed = await search("uploaded_image", [
      { key: F.assignedArtist, constraint_type: "equals", value: email },
      { key: F.claimState, constraint_type: "equals", value: CS.unclaimed }]);
    const open = await search("uploaded_image", [
      { key: F.assignedArtist, constraint_type: "equals", value: email },
      { key: F.claimState, constraint_type: "equals", value: CS.claimed }]);
    const underLimit = open.length < a.maxConcurrent;
    res.json({ email, limit: a.maxConcurrent, openCount: open.length, underLimit,
      claimable: underLimit ? unclaimed.map(mapOrder) : [], locked: underLimit ? [] : unclaimed.map(mapOrder),
      open: open.map(mapOrder) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/claim", async (req, res) => {
  const { email, orderId } = req.body;
  try { res.json(await withLock(orderId, () => tryClaim(orderId, email))); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin push: force an order onto a vendor (auto-claimed, over cap allowed).
app.post("/api/force-assign", requireAdmin, async (req, res) => {
  const { email, orderId } = req.body;
  try { res.json(await withLock(orderId, () => forceAssign(orderId, email))); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin dashboard: unclaimed orders still in rotation, surfaced oldest-first
// (FIFO) with age + rotation/pass counts so admin can spot ones worth pushing.
// Nothing is ever "parked" -- these are all still actively rotating.
app.get("/api/aging", requireAdmin, async (_req, res) => {
  try {
    const rows = await search("uploaded_image", [{ key: F.claimState, constraint_type: "equals", value: CS.unclaimed }]);
    const now = Date.now();
    const list = rows.map(o => {
      const created = new Date(o["Created Date"]).getTime();
      const minutesUnclaimed = Math.round((now - created) / 60000);
      return {
        id: o._id, ref: o[REF_FIELD] || o._id,
        currentArtist: o[F.assignedArtist] || "",
        minutesUnclaimed,
        rotations: o[F.rotationCount] || 0,
        passes: o.review_count || 0,
        aging: minutesUnclaimed >= AGING_MIN, // dashboard highlights these
      };
    });
    list.sort((a, b) => b.minutesUnclaimed - a.minutesUnclaimed); // oldest first
    res.json(list);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/", (_req, res) => res.send('Engine running. Vendor portal: /vendor/login'));

// ---- Mount the vendor portal (login, orders, claim, download, upload, run-as)
const { mountVendorPortal } = require("./vendor");
mountVendorPortal(app, {
  bubble, search, getOrder, patchOrder, artistByEmail, tryClaim,
  withLock, logEvent, F, CS, REF_FIELD, ADMIN_SECRET, BUBBLE_BASE, BUBBLE_TOKEN,
});

setInterval(sweep, SWEEP_SECONDS * 1000);
app.listen(PORT, () => console.log(`claim engine + vendor portal on http://localhost:${PORT}  (sweep every ${SWEEP_SECONDS}s)`));
