/* =============================================================================
   VENDOR PORTAL  —  mounts onto the claim engine (app.js).
   -----------------------------------------------------------------------------
   Vendors log in with accounts YOU create (stored in Bubble type Vendor_Login).
   They see their claimable + claimed orders, claim, download source files,
   upload the finished file (which flips the order's Pending -> no), all behind
   a session cookie. Admins can "run as" any vendor for full testing.

   Requires (package.json): express, cookie-parser, bcryptjs, multer
   New Bubble data type required: Vendor_Login
     fields: email (text), password_hash (text), must_change (yes/no),
             active (yes/no)
   Env: ADMIN_SECRET (already set) is reused as the admin login password here.
============================================================================= */

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const crypto = require("crypto");
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

// In-memory session store. Sessions are lost on restart (vendors just log in
// again) -- fine for a prototype. Move to Bubble/Redis later if needed.
const sessions = new Map(); // token -> { email, isAdmin, actingAs, created }
const SESSION_HOURS = 12;

function makeToken() { return crypto.randomBytes(32).toString("hex"); }

// ---- Client completion email (SendGrid) ----
// Key is read from the environment so the secret stays out of the code/repo.
// Set SENDGRID_API_KEY in Railway's Variables tab.
const SENDGRID_KEY = process.env.SENDGRID_API_KEY || "";
const MAIL_FROM_EMAIL = "contact@printreadyart.com";
const MAIL_FROM_NAME = "Print Ready Art";
const MAIL_BCC = "contact@printreadyart.com"; // matches the current "bcc: me"; set "" for none
const MAIL_ADMIN_TO = "contact@printreadyart.com"; // where vendor->admin messages land
const MAIL_ADMIN_CC = "brian@printreadyart.com";   // CC on vendor->admin messages
const OM = "order_message"; // Bubble Data API type slug for the message thread

// Required capabilities for an order (mirrors the engine, scoped-subset model):
// type cap, plus separations only on Vector, ofm/pfx only on Digitizing.
const TYPE_CAP = { "Vector": "vector", "Digitizing": "digitizing", "Digital (DTF/DTG)": "digital_printing" };
function requiredCapsFor(o) {
  const caps = []; const t = TYPE_CAP[o.Order_Type]; if (t) caps.push(t);
  if (o.Order_Type === "Vector" && o.Separations === "yes") caps.push("separations");
  if (o.Order_Type === "Digitizing") {
    if (o.OFM === "yes") caps.push("ofm");
    if (o.PXF === "yes") caps.push("pfx");
  }
  return caps;
}
function vendorCanDo(order, caps) {
  const need = requiredCapsFor(order);
  const have = (caps || []).map((c) => String(c).toLowerCase());
  return need.every((c) => have.includes(c));
}
/* ---- Write-once completion timestamps ---------------------------------------
   "Modified Date" is a BAD completion proxy: an order finished in 8h that gets an
   edit 3 days later reads as a 3-day order, because any later touch moves Modified
   Date. So the engine stamps two timestamps that are written EXACTLY ONCE and never
   moved: first_claimed_at and first_completed_at. Order speed = the gap between them.
   (Edit speed was always fine -- edit_request carries real Created Date / Completed.)

   Read tolerantly across casing variants: Bubble editor labels != Data API keys, and
   that has bitten us on image, Client_Special_Instructions and max_concurrent_orders. */
const FIRST_COMPLETED_KEYS = ["first_completed_at", "First_completed_at"];
const FIRST_CLAIMED_KEYS = ["first_claimed_at", "First_claimed_at"];
const readStamp = (o, keys) => { for (const k of keys) { if (o && o[k]) return o[k]; } return null; };
const firstCompletedOf = (o) => readStamp(o, FIRST_COMPLETED_KEYS);
// claimed_at is a legacy fallback ONLY: forceAssign re-stamps it on reassignment, so
// it can drift after first completion. first_claimed_at never does.
const firstClaimedOf = (o) => readStamp(o, FIRST_CLAIMED_KEYS) || (o && o.claimed_at) || null;
// Hours from first claim to first completion. Null (not zero, not a guess) when either
// stamp is missing -- orders completed before these fields existed are EXCLUDED from
// averages rather than measured with a poisoned value.
const orderSpeedHours = (o) => {
  const fc = firstCompletedOf(o), st = firstClaimedOf(o);
  if (!fc || !st) return null;
  const h = (new Date(fc).getTime() - new Date(st).getTime()) / 3600000;
  return h >= 0 ? h : null;
};
const completedAtMs = (o) => { const fc = firstCompletedOf(o); return fc ? new Date(fc).getTime() : null; };

/* ---- Edit fault classification (minimal) ------------------------------------
   An edit is either OUR mistake (vendor_error) or the client wanting something
   different (client_change), or unclear. Claude labels every new edit automatically;
   the label is the number. A human can override, which LOCKS the row so the
   classifier never touches it again.

   Config (model, confidence floor, the prompt itself) lives in ./fault-prompt.js.
   Only TWO fields are stored per edit:
     edit_fault    (text)   vendor_error | client_change | unclear
     fault_locked  (yes/no) a human set it; the classifier must not overwrite. */
const { FAULT_MODEL, FAULT_CONFIDENCE_FLOOR, FAULT_CODES, FAULT_PROMPT } = require("./fault-prompt");
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || "";
const AUTO_CLASSIFY_MIN = Number(process.env.FAULT_AUTO_CLASSIFY_MIN || 30);
const SWEEP_BATCH = Math.min(Math.max(Number(process.env.FAULT_SWEEP_BATCH || 25), 1), 100);
// Global fallback idle threshold (hours). Must match app.js IDLE_DEFAULT_HOURS -- app.js
// uses it for the reassign sweep; here it's only for the admin display default.
const IDLE_DEFAULT_HOURS = Number(process.env.IDLE_DEFAULT_HOURS || 5);
const FAULT_START_ISO = (() => {
  const raw = process.env.FAULT_START_DATE;
  if (raw) { const d = new Date(raw); if (!isNaN(d)) return d.toISOString();
    console.warn(`[fault] FAULT_START_DATE="${raw}" invalid -- using boot time`); }
  else console.warn("[fault] FAULT_START_DATE not set -- classifying edits after THIS BOOT. Pin it to survive redeploys.");
  return new Date().toISOString();
})();
const readField = (r, ...keys) => { for (const k of keys) { const v = r && r[k]; if (v !== undefined && v !== null && v !== "") return v; } return null; };
const normFault = (v) => { const f = String(v || "").toLowerCase().trim(); return FAULT_CODES.includes(f) ? f : null; };
const faultOf = (er) => normFault(readField(er, "edit_fault", "Edit_Fault"));
const isLocked = (er) => { const v = readField(er, "fault_locked", "Fault_Locked"); return v === true || v === "yes" || v === "true"; };

async function classifyEditFault(er, order) {
  if (!ANTHROPIC_KEY) return { ok: false, error: "ANTHROPIC_API_KEY not set" };
  const payload = {
    ORDER_TYPE: (order && order.Order_Type) || er.Order_Type || "",
    ORIGINAL_INSTRUCTIONS: (order && order.Special_Instructions) || "",
    CHANGES_REQUESTED: er.Changes_Needed || "",
    CLIENT_SELECTED_REASON: er.Edit_Reason || "",
  };
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: FAULT_MODEL, max_tokens: 150, system: FAULT_PROMPT, messages: [{ role: "user", content: JSON.stringify(payload) }] }),
    });
    if (!res.ok) return { ok: false, error: `Claude ${res.status}: ${(await res.text()).slice(0, 160)}` };
    const data = await res.json();
    const text = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("").trim();
    const clean = text.replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
    let parsed; try { parsed = JSON.parse(clean); } catch (_) { return { ok: false, error: "bad JSON: " + clean.slice(0, 100) }; }
    const fault = normFault(parsed.fault);
    if (!fault) return { ok: false, error: "unknown fault code" };
    let conf = Number(parsed.confidence); if (!(conf >= 0 && conf <= 1)) conf = 0;
    return { ok: true, fault: conf >= FAULT_CONFIDENCE_FLOOR ? fault : "unclear" };
  } catch (e) { return { ok: false, error: e.message }; }
}


function newSession(data) {
  const token = makeToken();
  sessions.set(token, { ...data, created: Date.now() });
  return token;
}
function getSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.created > SESSION_HOURS * 3600e3) { sessions.delete(token); return null; }
  return s;
}

// The effective vendor email for a session: if an admin is "acting as" someone,
// that's the email we operate on; otherwise the logged-in vendor's own email.
function effectiveEmail(s) { return s.actingAs || s.email; }

/* Stamp a vendor's activity. last_action_at on any deliberate action; last_upload_at
   additionally on a completed-order upload. Fire-and-forget: a stamp failure must never
   block the action it is recording, and a missing Bubble field just logs. Skipped when an
   admin is acting "as" a vendor, so run-as testing doesn't fake someone's activity. */
async function touchArtist(session, opts = {}) {
  try {
    if (session && session.actingAs) return;                 // admin run-as: don't fake activity
    const email = session && session.email;
    if (!email || email === "admin") return;
    const rows = await search("artist", [{ key: "email", constraint_type: "equals", value: String(email).toLowerCase() }]);
    const a = rows[0];
    if (!a) return;
    const patch = { last_action_at: Date.now() };
    if (opts.upload) patch.last_upload_at = Date.now();
    await bubble("PATCH", `/artist/${a._id}`, patch);
  } catch (e) { console.warn("[activity] stamp failed:", e.message); }
}

/**
 * mountVendorPortal(app, deps)
 *   app  - the express app from app.js
 *   deps - { bubble, search, getOrder, patchOrder, artistByEmail, tryClaim,
 *            withLock, logEvent, F, CS, REF_FIELD, ADMIN_SECRET, BUBBLE_BASE }
 */
function mountVendorPortal(app, deps) {
  const {
    bubble, search, getOrder, patchOrder, artistByEmail, tryClaim,
    withLock, logEvent, F, CS, REF_FIELD, ADMIN_SECRET, BUBBLE_BASE, BUBBLE_TOKEN,
  } = deps;

  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });
  app.use(cookieParser());

  // ---- Vendor_Login data access (stored in Bubble) -------------------------
  const VL = "vendor_login"; // Bubble Data API type slug
  async function findLogin(email) {
    const rows = await search(VL, [{ key: "email", constraint_type: "equals", value: email.toLowerCase() }]);
    return rows[0] || null;
  }
  async function createLogin(email, tempPassword) {
    const hash = await bcrypt.hash(tempPassword, 10);
    await bubble("POST", `/${VL}`, {
      email: email.toLowerCase(), password_hash: hash, must_change: true, active: true,
    });
  }
  async function setPassword(loginId, newPassword, mustChange = false) {
    const hash = await bcrypt.hash(newPassword, 10);
    await bubble("PATCH", `/${VL}/${loginId}`, { password_hash: hash, must_change: mustChange });
  }

  // ---- auth middleware ------------------------------------------------------
  function requireVendor(req, res, next) {
    const s = getSession(req.cookies.vp_session || "");
    if (!s) return res.redirect("/vendor/login");
    req.session = s;
    next();
  }
  function requireAdminLogin(req, res, next) {
    const s = getSession(req.cookies.vp_session || "");
    if (!s || !s.isAdmin) return res.status(403).send("Admins only.");
    req.session = s;
    next();
  }

  // ---- LOGIN ---------------------------------------------------------------
  app.post("/vendor/api/login", express.json(), async (req, res) => {
    try {
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");

      // Admin login: email "admin" + the ADMIN_SECRET as password.
      if (email === "admin") {
        if (!ADMIN_SECRET || password !== ADMIN_SECRET)
          return res.status(401).json({ ok: false, error: "Invalid login" });
        const token = newSession({ email: "admin", isAdmin: true });
        res.cookie("vp_session", token, { httpOnly: true, secure: true, sameSite: "lax" });
        return res.json({ ok: true, isAdmin: true });
      }

      const login = await findLogin(email);
      if (!login || login.active === false)
        return res.status(401).json({ ok: false, error: "Invalid login" });
      const match = await bcrypt.compare(password, login.password_hash || "");
      if (!match) return res.status(401).json({ ok: false, error: "Invalid login" });

      const token = newSession({ email });
      res.cookie("vp_session", token, { httpOnly: true, secure: true, sameSite: "lax" });
      touchArtist({ email });
      res.json({ ok: true, mustChange: login.must_change === true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  app.post("/vendor/api/logout", (req, res) => {
    sessions.delete(req.cookies.vp_session || "");
    res.clearCookie("vp_session");
    res.json({ ok: true });
  });

  // ---- CHANGE PASSWORD (first login forced) --------------------------------
  app.post("/vendor/api/change-password", express.json(), requireVendor, async (req, res) => {
    try {
      const s = req.session;
      if (s.isAdmin) return res.status(400).json({ ok: false, error: "Admin password is set via env" });
      const newPassword = String(req.body.newPassword || "");
      if (newPassword.length < 8) return res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });
      const login = await findLogin(s.email);
      if (!login) return res.status(404).json({ ok: false, error: "Account not found" });
      await setPassword(login._id, newPassword, false);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- ORDER LIST ----------------------------------------------------------
  function fileLinks(o) {
    // Surface any file-bearing fields on the order for download.
    const out = [];
    const push = (label, val) => {
      if (!val) return;
      const url = String(val).startsWith("//") ? "https:" + val : String(val);
      out.push({ label, url });
    };
    push("Artwork", o.image);
    if (Array.isArray(o.Supporting_Files)) o.Supporting_Files.forEach((f, i) => push(`Supporting ${i + 1}`, f));
    return out;
  }
  // Fetch a Team's vendor-facing docs, split by category. FAIL-SAFE: any error returns
  // empty, never throws. Template_1 & Template_3 + Instructions_1 are SEPARATIONS docs;
  // Template_2 + Instructions_2 are DIGITIZING docs.
  async function teamDocs(teamId, cache) {
    const empty = { sepTemplates: [], digTemplates: [], sepInstr: "", digInstr: "" };
    if (!teamId) return empty;
    if (cache && cache.has(teamId)) return cache.get(teamId);
    const linkify = (val) => (!val ? null : (String(val).startsWith("//") ? "https:" + val : String(val)));
    let docs = { sepTemplates: [], digTemplates: [], sepInstr: "", digInstr: "" };
    try {
      const t = await bubble("GET", `/team/${teamId}`).then(r => r.response);
      const t1 = linkify(t.Client_Template_1), t2 = linkify(t.Client_Template_2), t3 = linkify(t.Client_Template_3);
      if (t1) docs.sepTemplates.push({ label: "Separations Template", url: t1 });
      if (t3) docs.sepTemplates.push({ label: "Separations Template 2", url: t3 });
      if (t2) docs.digTemplates.push({ label: "Digitizing Template", url: t2 });
      docs.sepInstr = String(t.Client_Special_Instructions_1 || "").trim();
      docs.digInstr = String(t.Client_Special_Instructions_2 || "").trim();
    } catch (e) { console.warn("[teamDocs] lookup failed for team " + teamId + ":", e.message); }
    if (cache) cache.set(teamId, docs);
    return docs;
  }

  function orderView(o, team) {
    const thumb = o.image ? (String(o.image).startsWith("//") ? "https:" + o.image : String(o.image)) : "";
    const v = {
      id: o._id,
      orderNo: o["Order#"] || "",
      type: o.Order_Type || "",
      state: o[F.claimState] || "",
      claimDeadline: o[F.claimDeadline] || null,
      claimedAt: o.claimed_at || null,
      separations: o[F.separations] || "no",
      rush: o.Rush || "no",
      multiEdit: o["Multiple Edit Alert"] === true,
      specialInstructions: o.Special_Instructions || "",
      thumb,
      files: fileLinks(o),
      details: {
        ArtDims_Seps: o.ArtDims_Seps || "", FilmSizeSeps: o.FilmSizeSeps || "",
        ArtPlacement_Seps: o.ArtPlacement_Seps || "", Rush: o.Rush || "no",
        Height: o.Height || "", Width: o.Width || "",
        Unit: o.Unit || "", "cm/in": o["cm/in"] || "",
      },
    };
    if (team) v.team = team;
    return v;
  }

  // New_Orders holds extra Digitizing spec, joined to the order by Order#.
  // Confirmed keys: 3D_Puff (bool), fabric_content (lowercase), Placement.
  async function newOrdersDetail(orderNo) {
    if (!orderNo) return null;
    try {
      // Bubble Data API type is "New_Order" (capital, singular) -- NOT "new_orders".
      // This was silently returning null before, blanking digitizing specs.
      const rows = await search("New_Order", [{ key: "Order#", constraint_type: "equals", value: orderNo }]);
      const n = rows[0];
      if (!n) return null;
      const pick = (...keys) => { for (const k of keys) { const v = n[k]; if (v !== undefined && v !== null && v !== "") return v; } return ""; };
      return {
        puff: n["3D_Puff"] === true ? "Yes" : (n["3D_Puff"] === false ? "No" : ""),
        fabric: pick("fabric_content", "Fabric_content"),
        placement: pick("Placement", "placement"),
        proportionalTo: pick("Proportional_to", "proportional_to", "Proportional_To"),
        dimension: pick("Dimension", "dimension"),
        specialInstructions: pick("Special_Instructions", "special_instructions"),
      };
    } catch (e) { console.warn("[orders] New_Order lookup failed for " + orderNo + ":", e.message); return null; }
  }

  // Per-vendor monthly speeds, COMPUTED from claim -> completion (order) and
  // created -> completed (edit). Cached 5 min so the 30s portal refresh stays cheap.
  const _speedCache = new Map();
  const SPEED_TTL = 5 * 60 * 1000;
  async function monthlySpeeds(email) {
    const hit = _speedCache.get(email);
    if (hit && Date.now() - hit.at < SPEED_TTL) return hit;
    const monStart = new Date(); monStart.setDate(1); monStart.setHours(0, 0, 0, 0);
    const monIso = monStart.toISOString();
    let orderSpeed = null, editSpeed = null, ordersMonth = 0, editsMonth = 0;
    try {
      // Modified Date is a COARSE prefilter only -- it is always >= first_completed_at,
      // so this search is a superset. We never query on the new field (a wrong API key
      // would 400 the search); precision happens in code below.
      const done = await search("uploaded_image", [
        { key: "use_new_system", constraint_type: "equals", value: true },
        { key: F.assignedArtist, constraint_type: "equals", value: email },
        { key: F.claimState, constraint_type: "equals", value: "completed" },
        { key: "Modified Date", constraint_type: "greater than", value: monIso }]);
      const monStartMs = monStart.getTime();
      const doneThisMonth = done.filter((o) => { const ms = completedAtMs(o); return ms != null && ms >= monStartMs; });
      ordersMonth = doneThisMonth.length; let s = 0, n = 0;
      doneThisMonth.forEach((o) => { const h = orderSpeedHours(o); if (h != null) { s += h; n++; } });
      orderSpeed = n ? +(s / n).toFixed(1) : null;
    } catch (e) { console.warn("[orders] monthly order speed failed:", e.message); }
    try {
      let em = await search("edit_request", [
        { key: "Assigned_Artist", constraint_type: "equals", value: email },
        { key: "Completed", constraint_type: "greater than", value: monIso }]);
      // Keep only edits on new-system orders (edit_request has no flag of its own).
      const flags = await Promise.all(em.map(async (e) => {
        try { const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: e["Order#"] }]); return !!(m[0] && m[0].use_new_system === true); }
        catch (_) { return false; }
      }));
      em = em.filter((_, i) => flags[i]);
      editsMonth = em.length; let s = 0, n = 0;
      em.forEach((e) => { if (e["Created Date"] && e.Completed) { const h = (new Date(e.Completed).getTime() - new Date(e["Created Date"]).getTime()) / 3600000; if (h >= 0) { s += h; n++; } } });
      editSpeed = n ? +(s / n).toFixed(1) : null;
    } catch (e) { console.warn("[orders] monthly edit speed failed:", e.message); }
    /* EDIT REQUEST RATE. Definition matters -- vendors will argue about it, so it is
       stated exactly here and surfaced in the UI tooltip:
         editPct = edits OPENED this month against this vendor's work
                   / orders this vendor FIRST-COMPLETED this month
       (Edit speed above is a different cohort on purpose: edits RESOLVED this month.)

       vendorErrorPct counts only edits a human has adjudicated as vendor_error. It is
       returned as null until most of the month's edits are adjudicated (faultCoverage),
       because publishing a fault rate computed from a half-labelled set is worse than
       publishing nothing. The UI slot exists now and lights up on its own. */
    // Vendor-facing rate is ALL edits (fault-blind). Fault/vendor-error is admin-only and
    // computed separately on the dashboard, so it is neither computed nor sent here.
    let editPct = null, editsOpened = 0;
    try {
      let opened = await search("edit_request", [
        { key: "Assigned_Artist", constraint_type: "equals", value: email },
        { key: "Created Date", constraint_type: "greater than", value: monIso }]);
      const flags = await Promise.all(opened.map(async (e) => {
        try { const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: e["Order#"] }]); return !!(m[0] && m[0].use_new_system === true); }
        catch (_) { return false; }
      }));
      opened = opened.filter((_, i) => flags[i]);
      editsOpened = opened.length;
      if (ordersMonth > 0) editPct = +((editsOpened / ordersMonth) * 100).toFixed(1);
    } catch (e) { console.warn("[orders] monthly edit rate failed:", e.message); }
    const out = { at: Date.now(), orderSpeed, editSpeed, ordersMonth, editsMonth, editsOpened, editPct };
    _speedCache.set(email, out);
    return out;
  }

  // Send the "your order is ready" email to the client. Best-effort: any failure is
  // logged and swallowed so a mail hiccup never blocks order completion.
  // Resolve client email (User id -> user record -> nested auth email) and team name
  // (Team_Name id -> team record). Cached 10 min so the 30s dashboard refresh doesn't
  // re-fetch the same clients/teams repeatedly.
  const _userEmailCache = new Map();
  const _teamNameCache = new Map();
  const NAME_TTL = 10 * 60 * 1000;
  async function clientEmailById(id) {
    if (!id) return "";
    const hit = _userEmailCache.get(id);
    if (hit && Date.now() - hit.at < NAME_TTL) return hit.email;
    let email = "";
    try {
      const u = await bubble("GET", `/user/${id}`).then((r) => r.response);
      email = u && u.authentication && u.authentication.email && u.authentication.email.email ? u.authentication.email.email : "";
    } catch (e) { console.warn("[dashboard] client email lookup failed:", e.message); }
    _userEmailCache.set(id, { at: Date.now(), email });
    return email;
  }
  async function teamNameById(id) {
    if (!id) return "";
    const hit = _teamNameCache.get(id);
    if (hit && Date.now() - hit.at < NAME_TTL) return hit.name;
    let name = "";
    try {
      const t = await bubble("GET", `/team/${id}`).then((r) => r.response);
      name = t && t.Team_Name ? t.Team_Name : "";
    } catch (e) { console.warn("[dashboard] team name lookup failed:", e.message); }
    _teamNameCache.set(id, { at: Date.now(), name });
    return name;
  }

  async function sendCompletionEmail(o) {
    try {
      if (!SENDGRID_KEY) { console.warn("[email] SENDGRID_API_KEY not set -- skipping send"); return; }
      // Recipient: order's own Email field if populated, else resolve the client from
      // the User id -> user record -> authentication.email.email (nested in Bubble).
      let to = (o.Email && String(o.Email).trim()) ? String(o.Email).trim() : "";
      if (!to && o.User) {
        try {
          const u = await bubble("GET", `/user/${o.User}`).then((r) => r.response);
          to = u && u.authentication && u.authentication.email && u.authentication.email.email
            ? u.authentication.email.email : "";
        } catch (e) { console.warn("[email] user lookup failed:", e.message); }
      }
      if (!to) { console.warn(`[email] no client email for order ${o["Order#"]} -- skipping send`); return; }
      const orderNo = o["Order#"] || "";
      const subject = `Your PrintReadyArt Order# ${orderNo} is Complete`;
      const text = "Your order is ready!\n\nWe completed your files and uploaded them to your dashboard. Please login at PrintReadyArt.com to download the files.\n\nWe appreciate being part of your team!\n\nPrint Ready Art Team";
      const html = "Your order is ready!<br><br>We completed your files and uploaded them to your dashboard. Please login at <a href=\"https://printreadyart.com\">PrintReadyArt.com</a> to download the files.<br><br>We appreciate being part of your team!<br><br>Print Ready Art Team";
      const personalization = { to: [{ email: to }] };
      if (MAIL_BCC && MAIL_BCC.toLowerCase() !== to.toLowerCase()) personalization.bcc = [{ email: MAIL_BCC }];
      const payload = {
        personalizations: [personalization],
        from: { email: MAIL_FROM_EMAIL, name: MAIL_FROM_NAME },
        subject,
        content: [{ type: "text/plain", value: text }, { type: "text/html", value: html }],
      };
      const res = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method: "POST",
        headers: { Authorization: `Bearer ${SENDGRID_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.status >= 200 && res.status < 300) console.log(`[email] completion email sent to ${to} for order ${orderNo}`);
      else console.warn(`[email] SendGrid ${res.status}: ${await res.text()}`);
    } catch (e) { console.warn("[email] send failed:", e.message); }
  }

  // Generic SendGrid sender (best-effort) used by the messaging notifications.
  async function sendMail({ to, cc, subject, text, html }) {
    try {
      if (!SENDGRID_KEY) { console.warn("[email] SENDGRID_API_KEY not set -- skipping send"); return; }
      if (!to) { console.warn("[email] no recipient -- skipping send"); return; }
      const pers = { to: [{ email: to }] };
      if (cc) pers.cc = (Array.isArray(cc) ? cc : [cc]).filter(Boolean).map((e) => ({ email: e }));
      const content = [{ type: "text/plain", value: text }];
      if (html) content.push({ type: "text/html", value: html });
      const payload = { personalizations: [pers], from: { email: MAIL_FROM_EMAIL, name: MAIL_FROM_NAME }, subject, content };
      const res = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method: "POST", headers: { Authorization: `Bearer ${SENDGRID_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      if (!(res.status >= 200 && res.status < 300)) console.warn(`[email] SendGrid ${res.status}: ${await res.text()}`);
    } catch (e) { console.warn("[email] send failed:", e.message); }
  }

  // Notify the other party that a message arrived (deduped by the caller).
  async function notifyMessage(role, orderNo, senderEmail) {
    if (role === "vendor") {
      await sendMail({ to: MAIL_ADMIN_TO, cc: MAIL_ADMIN_CC,
        subject: `New message from a vendor on Order #${orderNo}`,
        text: `${senderEmail} sent a message on Order #${orderNo}.\n\nOpen the Orders dashboard to read and reply.`,
        html: `${senderEmail} sent a message on Order #${orderNo}.<br><br>Open the Orders dashboard to read and reply.` });
    } else {
      let vendorEmail = "";
      try {
        const rows = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: orderNo }]);
        vendorEmail = rows[0] ? String(rows[0][F.assignedArtist] || "") : "";
      } catch (e) { console.warn("[msg] vendor lookup failed:", e.message); }
      if (!vendorEmail) return;
      await sendMail({ to: vendorEmail,
        subject: `PrintReadyArt messaged you on Order #${orderNo}`,
        text: `PrintReadyArt sent you a message on Order #${orderNo}.\n\nLog in to your vendor portal to read and reply.`,
        html: `PrintReadyArt sent you a message on Order #${orderNo}.<br><br>Log in to your vendor portal to read and reply.` });
    }
  }

  // ---- Messaging endpoints (vendor <-> admin, per order) -------------------
  app.get("/vendor/api/messages", requireVendor, async (req, res) => {
    try {
      const orderNo = String(req.query.orderNo || "");
      if (!orderNo) return res.json({ messages: [] });
      const rows = await search(OM, [{ key: "order_no", constraint_type: "equals", value: orderNo }]);
      rows.sort((a, b) => new Date(a["Created Date"] || 0) - new Date(b["Created Date"] || 0));
      res.json({ messages: rows.map((m) => ({ role: m.sender_role, email: m.sender_email, body: m.body, at: m["Created Date"] })) });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post("/vendor/api/messages", express.json(), requireVendor, async (req, res) => {
    try {
      const s = req.session;
      const orderNo = String(req.body.orderNo || "").trim();
      const body = String(req.body.body || "").trim();
      if (!orderNo || !body) return res.status(400).json({ ok: false, error: "orderNo and body required" });
      const role = s.isAdmin ? "admin" : "vendor";
      const senderEmail = s.isAdmin ? MAIL_FROM_EMAIL : effectiveEmail(s);
      // Dedupe the email heads-up: only notify if the recipient has no unread message
      // from this sender on this order yet (a burst = one email, not ten).
      const recipientField = role === "admin" ? "read_by_vendor" : "read_by_admin";
      const existing = await search(OM, [{ key: "order_no", constraint_type: "equals", value: orderNo }]);
      const alreadyPending = existing.some((m) => m.sender_role === role && m[recipientField] !== true);
      await bubble("POST", `/${OM}`, {
        order_no: orderNo, sender_role: role, sender_email: senderEmail, body,
        read_by_admin: role === "admin", read_by_vendor: role === "vendor",
      });
      if (!alreadyPending) notifyMessage(role, orderNo, senderEmail).catch((e) => console.warn("[msg] notify failed:", e.message));
      if (role === "vendor") touchArtist(s);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  app.post("/vendor/api/messages/read", express.json(), requireVendor, async (req, res) => {
    try {
      const s = req.session;
      const orderNo = String(req.body.orderNo || "").trim();
      if (!orderNo) return res.json({ ok: true });
      const field = s.isAdmin ? "read_by_admin" : "read_by_vendor";
      const otherRole = s.isAdmin ? "vendor" : "admin";
      const rows = await search(OM, [{ key: "order_no", constraint_type: "equals", value: orderNo }]);
      const toMark = rows.filter((m) => m.sender_role === otherRole && m[field] !== true);
      for (const m of toMark) await bubble("PATCH", `/${OM}/${m._id}`, { [field]: true });
      res.json({ ok: true, marked: toMark.length });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  app.get("/vendor/api/orders", requireVendor, async (req, res) => {
    try {
      const email = effectiveEmail(req.session);
      const a = await artistByEmail(email);
      const limit = a ? a.maxConcurrent : 0;
      const myCaps = a ? a.capabilities : [];
      // SHARED POOL: every unclaimed order is visible to any vendor whose capabilities
      // match it -- not just orders pre-stamped to this vendor. We pull the whole
      // unclaimed pool and filter to the ones this vendor is eligible for.
      const pool = await search("uploaded_image", [
        { key: F.useNewSystem, constraint_type: "equals", value: true },
        { key: F.claimState, constraint_type: "equals", value: CS.unclaimed }]);
      const claimable = pool.filter((o) => vendorCanDo(o, myCaps));
      // OLDEST-FIRST, PER TYPE: only the single oldest unclaimed order of each type is
      // claimable now; newer ones of that type are "next in line" (locked) so vendors
      // can't cherry-pick ahead. Position within the type's line is sent for display.
      claimable.sort((a, b) => new Date(a["Created Date"] || 0) - new Date(b["Created Date"] || 0));
      const typeCount = {};
      const claimableViews = claimable.map((o) => {
        const type = o.Order_Type || "(none)";
        typeCount[type] = (typeCount[type] || 0) + 1;
        const pos = typeCount[type];
        return { id: o._id, orderNo: o["Order#"] || "", type: o.Order_Type || "", locked: pos > 1, pos };
      });
      const mine = await search("uploaded_image", [
        { key: F.assignedArtist, constraint_type: "equals", value: email },
        { key: F.claimState, constraint_type: "equals", value: CS.claimed }]);
      const teamCache = new Map();
      const claimedViews = await Promise.all(mine.map(async (o) => {
        const view = orderView(o, await teamDocs(o.Team_Name, teamCache));
        if ((o.Order_Type || "") === "Digitizing") {
          const nd = await newOrdersDetail(o["Order#"]);
          if (nd) view.details.newOrder = nd;
        }
        return view;
      }));
      // Edit requests: OPEN Edit_Request records (blank Completed) assigned to this vendor.
      // The table is the source of truth; we join to the order by Order# for original work.
      const linkify = (v) => (!v ? null : (String(v).startsWith("//") ? "https:" + v : String(v)));
      let openEdits = [];
      try {
        openEdits = await search("edit_request", [
          { key: "Assigned_Artist", constraint_type: "equals", value: email },
          { key: "Completed", constraint_type: "is_empty" }]);
      } catch (e) { console.warn("[orders] edit_request lookup failed:", e.message); }
      // Join each open edit to its order (uploaded_image) ONCE, then keep only edits whose
      // order is in the new system. edit_request has no use_new_system flag of its own, so
      // we must check the underlying order. This same lookup feeds the edit cards below.
      const editPairs = await Promise.all(openEdits.map(async (er) => {
        let order = null;
        try {
          const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: er["Order#"] }]);
          order = m[0] || null;
        } catch (e) { console.warn("[orders] order lookup failed for " + er["Order#"] + ":", e.message); }
        return { er, order };
      }));
      const newSysEdits = editPairs.filter((p) => p.order && p.order.use_new_system === true);
      // Cap load = claimed work + open edits (matches the engine's countClaimed). Open
      // edits consume slots so a vendor can't take new work until edits are cleared.
      // Per-bucket load (a): digitizing vs other (vector+digital). Edits count against
      // their original order's bucket. Each bucket has its own cap.
      const capDig = a ? a.capDigitizing : 0;
      const capOther = a ? a.capOther : 0;
      const isDig = (t) => (t || "") === "Digitizing";
      const digClaimed = mine.filter((o) => isDig(o.Order_Type)).length;
      const otherClaimed = mine.length - digClaimed;
      const digEdits = newSysEdits.filter((p) => isDig(p.er.Order_Type)).length;
      const otherEdits = newSysEdits.length - digEdits;
      const editCount = newSysEdits.length;
      const digLoad = digClaimed + digEdits;
      const otherLoad = otherClaimed + otherEdits;
      const load = mine.length + editCount;
      const underDig = digLoad < capDig;
      const underOther = otherLoad < capOther;
      const editViews = await Promise.all(newSysEdits.map(async ({ er, order }) => {
        const base = orderView(order, await teamDocs(order.Team_Name, teamCache));
        base.id = order._id; // "Upload revised" must target the ORDER
        base.edit = {
          reqId: er._id,
          changes: er.Changes_Needed || "",
          reason: er.Edit_Reason || "",
          created: er["Created Date"] || null,
          refs: [["Reference 1", er.File_1], ["Reference 2", er.File_2]]
            .map(([label, v]) => { const u = linkify(v); return u ? { label, url: u } : null; }).filter(Boolean),
        };
        return base;
      }));
      const sp = await monthlySpeeds(email);
      // Unread indicator (one cheap search piggybacked on this existing refresh):
      // admin messages this vendor hasn't read yet. Mark matching claimed/edit rows.
      try {
        const unread = await search(OM, [
          { key: "sender_role", constraint_type: "equals", value: "admin" },
          { key: "read_by_vendor", constraint_type: "equals", value: false }]);
        const unreadSet = new Set(unread.map((m) => String(m.order_no)));
        claimedViews.forEach((v) => { if (unreadSet.has(String(v.orderNo))) v.unread = true; });
        editViews.forEach((v) => { if (unreadSet.has(String(v.orderNo))) v.unread = true; });
      } catch (e) { console.warn("[orders] unread scan failed:", e.message); }
      res.json({
        email, limit, openCount: load, claimedCount: mine.length, editCount,
        capDig, capOther, digLoad, otherLoad, underDig, underOther,
        actingAs: req.session.actingAs || null,
        monthlyTimer: sp.orderSpeed, monthlyEditTimer: sp.editSpeed,
        monthlyCount: sp.ordersMonth, monthlyEdits: sp.editsMonth,
        // Vendor sees the all-edits rate only. vendorErrorPct is admin-only and is
        // deliberately NOT included in this payload -- not just hidden in the UI, absent
        // from the response, so it can't be read from the browser's network tab.
        editPct: sp.editPct, editsOpened: sp.editsOpened,
        edits: editViews,
        claimable: claimableViews,
        claimed: claimedViews,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ---- CLAIM ---------------------------------------------------------------
  app.post("/vendor/api/claim", express.json(), requireVendor, async (req, res) => {
    try {
      const email = effectiveEmail(req.session);
      const { orderId } = req.body;
      const result = await withLock(orderId, () => tryClaim(orderId, email));
      if (result && result.ok) touchArtist(req.session);
      res.json(result);
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- UPLOAD COMPLETED WORK  (real fields: image + Supporting_Files) ------
  // Preview -> single `image` field ; supporting files -> `Supporting_Files` list ;
  // Pending -> no. Bubble has NO /fileupload endpoint, and a LIST-of-files field will
  // only accept hosted URL strings (not raw base64). A SINGLE file field accepts the
  // base64 object and exposes the hosted URL on the next read. So supporting files are
  // converted to URLs one at a time through the `vendor_scratch_file` pad, then the URL
  // list is written to Supporting_Files. The pad is blanked afterward (best-effort).
  function bubbleFile(file) {
    return {
      filename: file.originalname,
      contents: file.buffer.toString("base64"),
      private: false,
    };
  }

  // Push one file's bytes through the scratch pad and return its hosted Bubble URL.
  /* ---- DST quality checks (digitizing) --------------------------------------
     Runs dst_check.py on the vendor's uploaded .dst, then compares the file's SIZE
     and sew DIRECTION against what the ORIGINAL order requested (read from New_Order,
     never from the vendor-overwritten uploaded_image). Returns:
       { ran, pass, failures:[...], size, direction, preview }
     Never throws: if anything goes wrong we return ran:false so the caller routes the
     order to review rather than silently passing it. */
  const SIZE_TOLERANCE_IN = Number(process.env.DST_SIZE_TOLERANCE || 0.1);

  function runDstScript(filePath) {
    return new Promise((resolve) => {
      execFile("python3", [path.join(__dirname, "dst_check.py"), filePath], { maxBuffer: 20 * 1024 * 1024, timeout: 30000 }, (err, stdout) => {
        if (err && !stdout) return resolve({ ok: false, error: err.message });
        try { resolve(JSON.parse(stdout)); } catch (e) { resolve({ ok: false, error: "bad checker output: " + String(stdout).slice(0, 120) }); }
      });
    });
  }

  // Parse the expected sew direction from the order's Placement string.
  function expectedDirection(placement) {
    const p = String(placement || "").toLowerCase();
    if (p.includes("center-out") || p.includes("center out") || p.includes("bottom-up") || p.includes("bottom up")) return "center_out";
    if (p.includes("left to right") || p.includes("left-to-right")) return "left_to_right";
    return null; // unknown / blank -> skip direction check
  }

  async function runDstChecks(dstFile, newOrder) {
    const result = { ran: false, pass: true, failures: [], notes: [] };
    if (!dstFile) return result;
    let tmp = "";
    try {
      tmp = path.join(os.tmpdir(), `dst_${Date.now()}_${Math.random().toString(36).slice(2)}.dst`);
      fs.writeFileSync(tmp, dstFile.buffer);
      const r = await runDstScript(tmp);
      result.ran = true;
      if (!r || r.ok === false) { result.pass = false; result.failures.push("Could not analyze the DST file" + (r && r.error ? ` (${r.error})` : "")); return result; }
      result.size = r.sizeInches || null;
      result.direction = r.direction || null;
      result.preview = r.preview || null;
      if (Array.isArray(r.notes)) result.notes.push(...r.notes);

      // SIZE check: Proportional_to picks the axis, Dimension is the target (a string).
      const prop = String((newOrder && newOrder.proportionalTo) || "").toLowerCase();
      const dim = parseFloat(String((newOrder && newOrder.dimension) || "").replace(/[^0-9.]/g, ""));
      if (prop && !isNaN(dim) && r.sizeInches) {
        const actual = prop.startsWith("tall") ? r.sizeInches.h : (prop.startsWith("wide") ? r.sizeInches.w : null);
        if (actual != null) {
          const off = Math.abs(actual - dim);
          if (off > SIZE_TOLERANCE_IN)
            result.failures.push(`Size off: requested ${dim}" ${prop === "tall" ? "tall" : "wide"}, file is ${actual.toFixed(2)}" (off by ${off.toFixed(2)}", tolerance ${SIZE_TOLERANCE_IN}")`);
        }
      } else {
        result.notes.push("Size not checked (order missing Proportional_to/Dimension).");
      }

      // DIRECTION check: compare the order's expected direction to the file's.
      const want = expectedDirection(newOrder && newOrder.placement);
      if (want && r.direction && r.direction !== "unclear") {
        if (r.direction !== want)
          result.failures.push(`Sew direction: order expects ${want === "center_out" ? "center-out/bottom-up (cap)" : "left-to-right (flat)"}, but the file appears to sew ${r.direction === "center_out" ? "center-out" : "left-to-right"}`);
      } else if (want && r.direction === "unclear") {
        result.notes.push("Sew direction inconclusive from the stitch file.");
      }

      result.pass = result.failures.length === 0;
      return result;
    } catch (e) {
      result.ran = true; result.pass = false; result.failures.push("QA check error: " + e.message);
      return result;
    } finally { if (tmp) { try { fs.unlinkSync(tmp); } catch (_) {} } }
  }

  async function uploadFileGetUrl(orderId, file) {
    await patchOrder(orderId, { vendor_scratch_file: bubbleFile(file) });
    const fresh = await getOrder(orderId);
    let url = fresh && fresh.vendor_scratch_file ? String(fresh.vendor_scratch_file) : "";
    if (!url) throw new Error(`Scratch upload returned no URL for ${file.originalname}`);
    if (url.startsWith("//")) url = "https:" + url;
    return url;
  }

  // Accepts: "preview" (single JPEG -> Image) and "supporting" (multiple -> Supporting_Files).
  const completedUpload = upload.fields([
    { name: "preview", maxCount: 1 },
    { name: "supporting", maxCount: 20 },
  ]);

  // Email the job's working instructions to the vendor themselves.
  // PRIVACY: the vendor portal deliberately carries ZERO client identity (no User id,
  // client email/name, team name, or Customer_PO#). This email must not reintroduce that
  // leak, so it is built field-by-field from work content only -- never from the raw order.
  // Files are sent as LINKS, not attachments (Bubble URLs work in mail; attachments would
  // mean base64 through SendGrid's ~30MB ceiling).
  app.post("/vendor/api/email-instructions", express.json(), requireVendor, async (req, res) => {
    try {
      const email = effectiveEmail(req.session);
      const orderId = String(req.body.orderId || "");
      const o = await getOrder(orderId);
      if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
      if (o[F.assignedArtist] !== email) return res.status(403).json({ ok: false, error: "Not your order" });

      // Allowed for claimed work or an open edit on this order (same rule as upload).
      let openEditReqs = [];
      try {
        openEditReqs = await search("edit_request", [
          { key: "Order#", constraint_type: "equals", value: o["Order#"] },
          { key: "Completed", constraint_type: "is_empty" }]);
      } catch (e) { console.warn("[instructions] edit lookup failed:", e.message); }
      if (o[F.claimState] !== CS.claimed && !openEditReqs.length)
        return res.status(400).json({ ok: false, error: "Order is not in your list" });

      const orderNo = o["Order#"] || orderId;
      const team = await teamDocs(o.Team_Name, null);
      const isDig = (o.Order_Type || "") === "Digitizing";
      const extra = isDig ? await newOrdersDetail(orderNo) : null;

      const L = [];
      L.push(`Order #${orderNo}`);
      L.push(`Type: ${o.Order_Type || "(none)"}`);
      if (o.Rush === "yes") L.push("RUSH");
      if ((o[F.separations] || "no") === "yes") L.push("Separations: yes");
      if (o.OFM === "yes") L.push("OFM: yes");
      if (o.PXF === "PXF") L.push("PXF: yes");
      L.push("");

      const spec = [];
      const addSpec = (k, v) => { if (v !== undefined && v !== null && String(v).trim() !== "") spec.push(`  ${k}: ${v}`); };
      // Lead with the digitizing essentials (same order the vendor sees on screen), then
      // the separations/common fields. `extra` is the New_Order record for digitizing.
      if (extra) {
        if (extra.dimension && extra.proportionalTo) addSpec("Requested size", `${extra.dimension}" ${String(extra.proportionalTo).toLowerCase()}`);
        const pl = String(extra.placement || "").toLowerCase();
        const kind = (pl.includes("round") || pl.includes("hat") || pl.includes("cap")) ? "Cap / Round (bottom-up, center-out)" : ((pl.includes("flat") || pl.includes("left to right")) ? "Flat (left-to-right)" : "");
        if (kind) addSpec("Type", kind);
        if (extra.specialInstructions) addSpec("Special instructions", extra.specialInstructions);
      }
      addSpec("Height", o.Height); addSpec("Width", o.Width);
      addSpec("Units", o["cm/in"]); addSpec("Stitch count", o.Stitch_Count);
      addSpec("Number of logos", o.Unit);
      addSpec("Art size", o.ArtDims_Seps); addSpec("Film size", o.FilmSizeSeps);
      addSpec("Art placement", o.ArtPlacement_Seps);
      if (extra) {
        addSpec("Placement", extra.placement); addSpec("3D puff", extra.puff); addSpec("Fabric", extra.fabric);
      }
      if (spec.length) { L.push("SPECS"); L.push(...spec); L.push(""); }

      if (o.Special_Instructions) { L.push("SPECIAL INSTRUCTIONS"); L.push(`  ${o.Special_Instructions}`); L.push(""); }

      if (openEditReqs.length) {
        L.push("EDIT REQUESTED");
        for (const er of openEditReqs) {
          if (er.Changes_Needed) L.push(`  Changes: ${er.Changes_Needed}`);
          if (er.Edit_Reason) L.push(`  Reason: ${er.Edit_Reason}`);
        }
        L.push("");
      }

      const teamInstr = isDig ? team.digInstr : team.sepInstr;
      if (teamInstr) { L.push("TEAM INSTRUCTIONS"); L.push(`  ${teamInstr}`); L.push(""); }

      const links = fileLinks(o);
      if (links.length) { L.push("FILES"); links.forEach((f) => L.push(`  ${f.label}: ${f.url}`)); L.push(""); }

      const tmpl = isDig ? team.digTemplates : team.sepTemplates;
      if (tmpl && tmpl.length) { L.push("TEMPLATES"); tmpl.forEach((t) => L.push(`  ${t.label || "Template"}: ${t.url}`)); L.push(""); }

      L.push("Links open the files directly. Do not reply to this email --");
      L.push("use the message thread on the order in the portal.");

      await sendMail({ to: email, subject: `PrintReadyArt Order #${orderNo} - job instructions`, text: L.join("\n") });
      console.log(`[instructions] order ${orderNo} emailed to ${email}`);
      touchArtist(req.session);
      res.json({ ok: true, sentTo: email });
    } catch (e) { console.error("[instructions]", e.message); res.status(500).json({ ok: false, error: e.message }); }
  });

  app.post("/vendor/api/upload", requireVendor, completedUpload, async (req, res) => {
    try {
      const email = effectiveEmail(req.session);
      const orderId = req.body.orderId;

      // Verify this order belongs to this vendor; allow either claimed work or an open edit.
      const o = await getOrder(orderId);
      if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
      if (o[F.assignedArtist] !== email) return res.status(403).json({ ok: false, error: "Not your order" });
      // Open edit request for this order assigned to this vendor? (table is source of truth)
      let openEditReqs = [];
      try {
        openEditReqs = await search("edit_request", [
          { key: "Order#", constraint_type: "equals", value: o["Order#"] },
          { key: "Completed", constraint_type: "is_empty" }]);
      } catch (e) { console.warn("[upload] edit lookup failed:", e.message); }
      const isEditSubmit = openEditReqs.length > 0;
      if (o[F.claimState] !== CS.claimed && !isEditSubmit)
        return res.status(400).json({ ok: false, error: "Order is not in your claimed list" });

      const previewFile = req.files?.preview?.[0] || null;
      const supportFiles = req.files?.supporting || [];
      if (!previewFile && supportFiles.length === 0)
        return res.status(400).json({ ok: false, error: "Attach at least a preview or a file" });

      // Embroidery = "Digitizing" order type: REQUIRES height, width, stitch count.
      const isEmbroidery = (o.Order_Type || "").toLowerCase() === "digitizing";
      const height = String(req.body.height || "").trim();
      const width  = String(req.body.width  || "").trim();
      const stitch = String(req.body.stitchCount || "").trim();
      if (isEmbroidery && (!height || !width || !stitch))
        return res.status(400).json({ ok: false, error: "Digitizing orders require Height, Width, and Stitch Count" });

      // Number of logos -> Artist_reported_count, required on ALL order types.
      const logos = String(req.body.logos || "").trim();
      if (!logos) return res.status(400).json({ ok: false, error: "Number of logos is required" });

      // ---- Automated QA on digitizing uploads --------------------------------
      // Find the .dst among supporting files, run size + direction checks against the
      // ORIGINAL request (New_Order table). A failure routes the order to needs_review
      // instead of completed; a pass completes normally. Skipped for edit re-submits
      // (the client already asked for specific changes) and non-digitizing orders.
      let qa = { ran: false, pass: true, failures: [], preview: null };
      if (isEmbroidery && !isEditSubmit) {
        const dstFile = supportFiles.find((f) => /\.dst$/i.test(f.originalname || ""));
        if (dstFile) {
          const no = await newOrdersDetail(o["Order#"]);
          qa = await runDstChecks(dstFile, no);
          console.log(`[qa] order ${o["Order#"]}: ran=${qa.ran} pass=${qa.pass} failures=${qa.failures.length}`);
        } else {
          console.log(`[qa] order ${o["Order#"]}: no .dst among uploads -- skipped`);
        }
      }
      const goToReview = qa.ran && !qa.pass;

      const patch = {
        Pending: false, Edit_Requested: false,
        [F.claimState]: goToReview ? "needs_review" : "completed",
        artist_reported_count: Number(logos),
      };
      if (goToReview) {
        // Store why it failed + the preview so the admin review slide-over can show it.
        patch.review_reasons = qa.failures.join(" | ");
        patch.review_flagged_at = Date.now();
        if (qa.preview) patch.review_preview = "data:image/png;base64," + qa.preview;
      }

      if (isEmbroidery) {
        // Bubble's Height/Width/Stitch_Count are TEXT fields (the read side falls back to
        // ""), so send the trimmed strings as-is rather than coercing to Number.
        patch.Height = height;
        patch.Width = width;
        patch.Stitch_Count = stitch;
      }

      // Preview -> single `image` field (base64 object on a single field works).
      if (previewFile) {
        patch.image = bubbleFile(previewFile);
      }

      // Supporting files -> convert each to a hosted URL via the scratch pad, then
      // OVERRIDE Supporting_Files with the URL list (a list field only takes URLs).
      let usedScratch = false;
      if (supportFiles.length) {
        const urls = [];
        for (const f of supportFiles) urls.push(await uploadFileGetUrl(orderId, f));
        patch.Supporting_Files = urls;
        usedScratch = true;
      }

      // Final atomic completion write. Note: on an edit this also flips Edit_Requested
      // back to false (in patch above) and writes the revised files onto the order.
      await patchOrder(orderId, patch);

      // WRITE-ONCE first-completion stamp. Skipped when the order is going to review --
      // it isn't actually completed yet. Two additional guards, both needed:
      //   !isEditSubmit  -- an edit re-upload must never move the original completion time
      //   !firstCompletedOf(o) -- nor may a plain re-upload before any edit exists
      if (!goToReview && !isEditSubmit && !firstCompletedOf(o)) {
        try { await patchOrder(orderId, { first_completed_at: Date.now() }); }
        catch (e) { console.warn("[stamp] first_completed_at write failed:", e.message); }
      }

      // Edit submit: stamp the open Edit_Request record(s) Completed = now so they drop
      // out of the vendor's edit queue into history. Best-effort: a failure here doesn't
      // undo the fix already written to the order.
      if (isEditSubmit) {
        try {
          for (const r of openEditReqs) {
            await bubble("PATCH", `/edit_request/${r._id}`, { Completed: Date.now() });
          }
          console.log(`[edit] order ${o["Order#"]} revised by ${email}; ${openEditReqs.length} edit record(s) marked complete`);
        } catch (e) { console.warn("[upload] edit-record close failed:", e.message); }
      }

      // Best-effort: blank the scratch pad. It never holds real data, so a lingering
      // value is harmless and gets overwritten on the next upload.
      if (usedScratch) {
        try { await patchOrder(orderId, { vendor_scratch_file: "" }); }
        catch (e) { console.warn("[upload] scratch clear failed:", e.message); }
      }

      // Client "your order is ready" email -- ONLY when the order is actually complete.
      // An order routed to review has NOT passed, so the client is not notified yet; the
      // email fires later when an admin approves it.
      if (!goToReview) {
        if (isEditSubmit) {
          await sendCompletionEmail(o);
        } else if (String(o.message_sent || "").toLowerCase() !== "yes") {
          await sendCompletionEmail(o);
          try { await patchOrder(orderId, { message_sent: "yes" }); }
          catch (e) { console.warn("[email] message_sent flag write failed:", e.message); }
        }
      }

      await logEvent(orderId, email, goToReview ? "flagged_for_review" : (isEditSubmit ? "edit_revised" : "completed_uploaded"),
        goToReview ? qa.failures.join(" | ") : `${previewFile ? "preview" : "no preview"}; ${supportFiles.length} supporting file(s)`);
      touchArtist(req.session, { upload: true });
      res.json({ ok: true, edit: isEditSubmit, review: goToReview, failures: goToReview ? qa.failures : [], preview: !!previewFile, supporting: supportFiles.length });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- REVIEW BUCKET: approve or reject a QA-flagged order -----------------
  // Approve: the order passes after human review -> complete it and fire the client
  // "your order is ready" email (once, guarded like the normal completion path).
  app.post("/vendor/api/admin/review-approve", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const id = String(req.body.id || "");
      if (!id) return res.status(400).json({ ok: false, error: "Need order id" });
      const o = await getOrder(id);
      if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
      await patchOrder(id, { [F.claimState]: "completed", Pending: false, review_reasons: "", review_flagged_at: null });
      // First-completion stamp (write-once) now that it's truly complete.
      if (!firstCompletedOf(o)) { try { await patchOrder(id, { first_completed_at: Date.now() }); } catch (_) {} }
      if (String(o.message_sent || "").toLowerCase() !== "yes") {
        await sendCompletionEmail(o);
        try { await patchOrder(id, { message_sent: "yes" }); } catch (_) {}
      }
      try { await logEvent(id, req.session.email || "admin", "review_approved", "admin approved flagged order"); } catch {}
      console.log(`[review] order ${o["Order#"] || id} APPROVED by ${req.session.email || "admin"}`);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Reject: send it back to the vendor with notes, like an edit. The order returns to the
  // vendor's claimed queue; the rejection note rides on Special_Instructions-style feedback.
  app.post("/vendor/api/admin/review-reject", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const id = String(req.body.id || "");
      const notes = String(req.body.notes || "").trim();
      if (!id) return res.status(400).json({ ok: false, error: "Need order id" });
      if (!notes) return res.status(400).json({ ok: false, error: "Rejection notes are required" });
      const o = await getOrder(id);
      if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
      // Back to the assigned vendor as claimed work, with the reviewer's notes attached.
      await patchOrder(id, {
        [F.claimState]: "claimed", Pending: true,
        review_reasons: "", review_flagged_at: null,
        review_rejected_notes: notes, review_rejected_at: Date.now(),
      });
      // Message the vendor the rejection so it surfaces in their thread.
      try {
        await bubble("POST", "/order_message", {
          order_no: o["Order#"] || "", sender_role: "admin", sender_email: req.session.email || "admin",
          body: "Your submission was returned for changes: " + notes,
          read_by_admin: true, read_by_vendor: false,
        });
      } catch (e) { console.warn("[review] reject message failed:", e.message); }
      try { await logEvent(id, req.session.email || "admin", "review_rejected", notes); } catch {}
      console.log(`[review] order ${o["Order#"] || id} REJECTED by ${req.session.email || "admin"}: ${notes}`);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- ADMIN: list vendors, create logins, run-as --------------------------
  app.get("/vendor/api/admin/vendors", requireAdminLogin, async (_req, res) => {
    try {
      const artists = await search("artist", [{ key: "is_active_vendor", constraint_type: "equals", value: true }]);
      const logins = await search(VL, []);
      const haveLogin = new Set(logins.map(l => (l.email || "").toLowerCase()));
      res.json(artists.map(a => ({
        email: (a.email || "").toLowerCase(),
        name: a.contact || a.email,
        hasLogin: haveLogin.has((a.email || "").toLowerCase()),
      })));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post("/vendor/api/admin/create-login", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const email = String(req.body.email || "").toLowerCase().trim();
      const temp = String(req.body.tempPassword || "").trim();
      if (!email || temp.length < 8) return res.status(400).json({ ok: false, error: "Need email + temp password (8+ chars)" });
      if (await findLogin(email)) return res.status(400).json({ ok: false, error: "Login already exists" });
      await createLogin(email, temp);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Create a brand-new vendor: a new artist record (order-ready) + optional login.
  app.post("/vendor/api/admin/create-vendor", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const email = String(req.body.email || "").toLowerCase().trim();
      const contact = String(req.body.contact || "").trim();
      const temp = String(req.body.tempPassword || "").trim();
      if (!email) return res.status(400).json({ ok: false, error: "Email is required" });
      if (temp && temp.length < 8) return res.status(400).json({ ok: false, error: "Temp password must be 8+ characters" });
      const rec = {
        email,
        contact: contact || email,
        is_active_vendor: req.body.active !== false,
        capabilities: Array.isArray(req.body.capabilities)
          ? [...new Set(req.body.capabilities.map((s) => String(s).toLowerCase().trim()).filter(Boolean))] : [],
      };
      if (req.body.maxDigitizing !== undefined && req.body.maxDigitizing !== "" && req.body.maxDigitizing !== null)
        rec.max_concurrent_digitizing = Number(req.body.maxDigitizing);
      if (req.body.maxOther !== undefined && req.body.maxOther !== "" && req.body.maxOther !== null)
        rec.max_concurrent_orders = Number(req.body.maxOther);
      if (req.body.idleThreshold !== undefined && req.body.idleThreshold !== "" && req.body.idleThreshold !== null)
        rec.idle_threshold_hours = Number(req.body.idleThreshold);
      if (req.body.phone) rec["phone number"] = String(req.body.phone).trim();
      await bubble("POST", "/artist", rec);
      console.log(`[admin] new vendor created: ${email}`);
      let loginCreated = false;
      if (temp && !(await findLogin(email))) { await createLogin(email, temp); loginCreated = true; }
      res.json({ ok: true, loginCreated });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Run-as: admin starts impersonating a vendor (full actions, logged).
  app.post("/vendor/api/admin/run-as", express.json(), requireAdminLogin, async (req, res) => {
    const email = String(req.body.email || "").toLowerCase().trim();
    req.session.actingAs = email;
    console.log(`[run-as] admin now acting as ${email}`);
    try { await logEvent("", email, "admin_run_as_start", "admin impersonation started"); } catch {}
    res.json({ ok: true, actingAs: email });
  });
  app.post("/vendor/api/admin/stop-run-as", requireAdminLogin, (req, res) => {
    const was = req.session.actingAs;
    req.session.actingAs = null;
    console.log(`[run-as] admin stopped acting as ${was}`);
    res.json({ ok: true });
  });

  // ---- VENDOR CONTROLS: capabilities, concurrency limit, active on/off ------
  // Lists every artist (the artist type = vendors; clients live in the user type).
  app.get("/vendor/api/admin/vendor-controls", requireAdminLogin, async (_req, res) => {
    try {
      const artists = await search("artist", []);
      const rows = artists.map((a) => ({
        id: a._id,
        email: (a.email || "").toLowerCase(),
        contact: a.contact || "",
        capabilities: Array.isArray(a.capabilities) ? a.capabilities.map((c) => String(c).toLowerCase()) : [],
        maxDigitizing: (a.max_concurrent_digitizing === 0 || a.max_concurrent_digitizing) ? a.max_concurrent_digitizing : (a.Max_concurrent_digitizing != null ? a.Max_concurrent_digitizing : ""),
        maxOther: (a.max_concurrent_orders === 0 || a.max_concurrent_orders) ? a.max_concurrent_orders : (a.Max_concurrent_orders != null ? a.Max_concurrent_orders : ""),
        idleThreshold: (a.idle_threshold_hours === 0 || a.idle_threshold_hours) ? a.idle_threshold_hours : (a.Idle_threshold_hours != null ? a.Idle_threshold_hours : ""),
        active: a.is_active_vendor === true,
      })).sort((x, y) => (x.email > y.email ? 1 : -1));
      res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Save one vendor's controls. Writes confirmed lowercase keys; only sets provided fields.
  app.post("/vendor/api/admin/vendor-controls", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const id = String(req.body.id || "");
      if (!id) return res.status(400).json({ ok: false, error: "Missing vendor id" });
      const patch = {};
      if (Array.isArray(req.body.capabilities))
        patch.capabilities = [...new Set(req.body.capabilities.map((s) => String(s).toLowerCase().trim()).filter(Boolean))];
      if (req.body.maxDigitizing !== undefined)
        patch.max_concurrent_digitizing = (req.body.maxDigitizing === "" || req.body.maxDigitizing === null) ? 0 : Number(req.body.maxDigitizing);
      if (req.body.maxOther !== undefined)
        patch.max_concurrent_orders = (req.body.maxOther === "" || req.body.maxOther === null) ? 0 : Number(req.body.maxOther);
      if (req.body.idleThreshold !== undefined)
        patch.idle_threshold_hours = (req.body.idleThreshold === "" || req.body.idleThreshold === null) ? 0 : Number(req.body.idleThreshold);
      if (typeof req.body.active === "boolean")
        patch.is_active_vendor = req.body.active;
      await bubble("PATCH", `/artist/${id}`, patch);
      console.log(`[admin] vendor ${id} updated: ${JSON.stringify(patch)}`);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- ADMIN ORDERS DASHBOARD: all pending orders + push/reassign/cancel -----
  app.get("/vendor/api/admin/dashboard", requireAdminLogin, async (_req, res) => {
    try {
      const [artists, pendingRaw, allOpenEdits, reviewOrders] = await Promise.all([
        search("artist", []),
        search("uploaded_image", [
          { key: "use_new_system", constraint_type: "equals", value: true },
          { key: "Pending", constraint_type: "equals", value: true }]),
        search("edit_request", [{ key: "Completed", constraint_type: "is_empty" }]),
        search("uploaded_image", [
          { key: "use_new_system", constraint_type: "equals", value: true },
          { key: F.claimState, constraint_type: "equals", value: "needs_review" }]),
      ]);
      // Merge review orders (Pending=false, so absent from the pending query) into the list.
      const seen = new Set(pendingRaw.map((o) => o._id));
      const pending = pendingRaw.concat((reviewOrders || []).filter((o) => !seen.has(o._id)));
      const now = Date.now();
      // edit_request has no use_new_system flag; keep only edits whose order is a new-system
      // order. Edits reopen the order to Pending=true, so a new-system edit's order is always
      // in the (use_new_system-gated) `pending` set above. This also keeps the "Edits pending"
      // count consistent with the row badges, which only attach to orders shown in the list.
      const pendingNos = new Set(pending.map((o) => String(o["Order#"] || "")));
      const openEdits = allOpenEdits.filter((er) => pendingNos.has(String(er["Order#"] || "")));
      const editsByVendor = {};
      openEdits.forEach((e) => { const a = String(e.Assigned_Artist || "").toLowerCase(); if (a) editsByVendor[a] = (editsByVendor[a] || 0) + 1; });
      // Open edits keyed by Order# so we can badge the order rows and show edit details.
      const linkifyD = (v) => (!v ? null : (String(v).startsWith("//") ? "https:" + v : String(v)));
      const editByNo = {};
      openEdits.forEach((er) => {
        const no = String(er["Order#"] || ""); if (!no) return;
        if (!editByNo[no]) editByNo[no] = {
          id: er._id,
          changes: er.Changes_Needed || "", reason: er.Edit_Reason || "",
          artist: er.Assigned_Artist || "", created: er["Created Date"] || null,
          // Two fields only: the answer, and whether a human locked it.
          fault: faultOf(er), locked: isLocked(er),
          refs: [["Reference 1", er.File_1], ["Reference 2", er.File_2]]
            .map(([label, v]) => { const u = linkifyD(v); return u ? { label, url: u } : null; }).filter(Boolean),
        };
      });
      // An order is only ACTUALLY claimed when claim_state === "claimed". The engine
      // pre-stamps nothing now (shared pool), but legacy rows may still carry a stamp;
      // claim_state is the only source of truth for "claimed".
      const isClaimed = (o) => (o[F.claimState] || "") === "claimed";
      const inReview = (o) => (o[F.claimState] || "") === "needs_review";
      const orders = pending.map((o) => {
        const created = o["Created Date"] ? (now - new Date(o["Created Date"]).getTime()) / 3600000 : null;
        const claimed = (isClaimed(o) && o.claimed_at) ? (now - new Date(o.claimed_at).getTime()) / 3600000 : null;
        const edit = editByNo[String(o["Order#"] || "")] || null;
        return {
          id: o._id, orderNo: o["Order#"] || "", ref: o["Customer_PO#"] || "", type: o.Order_Type || "",
          user: o.User || "", teamId: o.Team_Name || "", state: o[F.claimState] || "",
          // Review orders keep their assigned artist visible so the reviewer knows who to reject to.
          assigned: (isClaimed(o) || inReview(o)) ? String(o[F.assignedArtist] || "") : "",
          reqCaps: requiredCapsFor(o),
          thumb: o.image ? (String(o.image).startsWith("//") ? "https:" + o.image : String(o.image)) : "",
          createdHours: created != null ? +created.toFixed(2) : null,
          claimedHours: claimed != null ? +claimed.toFixed(2) : null,
          separations: o[F.separations] || "no", rush: o.Rush || "no",
          multiEdit: o["Multiple Edit Alert"] === true,
          hasEdit: !!edit, edit: edit,
          inReview: inReview(o),
          reviewReasons: inReview(o) ? String(o.review_reasons || "") : "",
          reviewPreview: inReview(o) ? String(o.review_preview || "") : "",
        };
      }).sort((a, b) => {
        const av = a.claimedHours != null ? a.claimedHours : -1, bv = b.claimedHours != null ? b.claimedHours : -1;
        if (av !== bv) return bv - av;
        return (b.createdHours || 0) - (a.createdHours || 0);
      });
      const knownTypes = ["Vector", "Digitizing", "Digital (DTF/DTG)"];
      const hSinceClaim = (o) => (isClaimed(o) && o.claimed_at) ? (now - new Date(o.claimed_at).getTime()) / 3600000 : null;
      const totals = {
        pending: pending.length,
        unassigned: pending.filter((o) => !isClaimed(o)).length,
        openEdits: openEdits.length,
        aging: pending.filter((o) => {
          if (isClaimed(o)) { const h = hSinceClaim(o); return h != null && h > 14; }
          const c = o["Created Date"] ? (now - new Date(o["Created Date"]).getTime()) / 3600000 : null;
          return c != null && c > 3;
        }).length,
        multiEdit: pending.filter((o) => o["Multiple Edit Alert"] === true).length,
        needsReview: pending.filter((o) => inReview(o)).length,
        vector: pending.filter((o) => o.Order_Type === "Vector").length,
        digitizing: pending.filter((o) => o.Order_Type === "Digitizing").length,
        digital: pending.filter((o) => o.Order_Type === "Digital (DTF/DTG)").length,
        other: pending.filter((o) => !knownTypes.includes(o.Order_Type)).length,
      };
      const dayStart = new Date(); dayStart.setHours(0, 0, 0, 0); const iso = dayStart.toISOString();
      const monStart = new Date(); monStart.setDate(1); monStart.setHours(0, 0, 0, 0); const monIso = monStart.toISOString();

      // ---- Per-vendor computed metrics (from live data, not stored fields) ----
      const byV = {};
      const bucket = (email) => {
        email = String(email || "").toLowerCase(); if (!email) return null;
        if (!byV[email]) byV[email] = { op: 0, ag: 0, ep: 0, ot: 0, om: 0, et: 0, em: 0, osT: [0, 0], osM: [0, 0], esM: [0, 0], digOp: 0, otherOp: 0, digEp: 0, otherEp: 0, eo: 0, ve: 0 };
        return byV[email];
      };
      const orderSpeedH = orderSpeedHours; // write-once stamps; see module-level helpers
      const editSpeedH = (e) => { if (!e["Created Date"] || !e.Completed) return null; const h = (new Date(e.Completed).getTime() - new Date(e["Created Date"]).getTime()) / 3600000; return h >= 0 ? h : null; };
      const dayStartMs = dayStart.getTime(), monStartMs = monStart.getTime();
      pending.forEach((o) => { if (!isClaimed(o)) return; const b = bucket(o[F.assignedArtist]); if (!b) return; b.op++; if ((o.Order_Type || "") === "Digitizing") b.digOp++; else b.otherOp++; const h = hSinceClaim(o); if (h != null && h > 14) b.ag++; });
      openEdits.forEach((e) => { const b = bucket(e.Assigned_Artist); if (!b) return; b.ep++; if ((e.Order_Type || "") === "Digitizing") b.digEp++; else b.otherEp++; });
      // "Done today/month" counts REAL first-completions. Searching on Modified Date alone
      // double-counted: an order completed days ago whose edit lands today still matches
      // claim_state=completed + modified-today. Modified Date stays as a coarse prefilter
      // (always >= first_completed_at); first_completed_at decides membership.
      try {
        const done = await search("uploaded_image", [
          { key: "use_new_system", constraint_type: "equals", value: true },
          { key: F.claimState, constraint_type: "equals", value: "completed" },
          { key: "Modified Date", constraint_type: "greater than", value: iso }]);
        const doneToday = done.filter((o) => { const ms = completedAtMs(o); return ms != null && ms >= dayStartMs; });
        totals.completedToday = doneToday.length;
        doneToday.forEach((o) => { const b = bucket(o[F.assignedArtist]); if (!b) return; b.ot++; const h = orderSpeedH(o); if (h != null) { b.osT[0] += h; b.osT[1]++; } });
      } catch (e) { console.warn("[dashboard] completedToday failed:", e.message); totals.completedToday = null; }
      try {
        const mo = await search("uploaded_image", [
          { key: "use_new_system", constraint_type: "equals", value: true },
          { key: F.claimState, constraint_type: "equals", value: "completed" },
          { key: "Modified Date", constraint_type: "greater than", value: monIso }]);
        const doneMonth = mo.filter((o) => { const ms = completedAtMs(o); return ms != null && ms >= monStartMs; });
        totals.completedMonth = doneMonth.length;
        doneMonth.forEach((o) => { const b = bucket(o[F.assignedArtist]); if (!b) return; b.om++; const h = orderSpeedH(o); if (h != null) { b.osM[0] += h; b.osM[1]++; } });
      } catch (e) { console.warn("[dashboard] completedMonth failed:", e.message); totals.completedMonth = null; }
      // Completed-edit metrics are on orders that are no longer pending, so the pending-set
      // trick doesn't apply -- look each edit's order up (cached, and seeded with the
      // already-known new-system pending orders) and keep only new-system ones.
      const nsCache = new Map();
      pendingNos.forEach((no) => nsCache.set(no, true));
      const isNewSysOrder = async (no) => {
        no = String(no || ""); if (!no) return false;
        if (nsCache.has(no)) return nsCache.get(no);
        let v = false;
        try { const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: no }]); v = !!(m[0] && m[0].use_new_system === true); }
        catch (e) { console.warn("[dashboard] new-system lookup failed for " + no + ":", e.message); }
        nsCache.set(no, v); return v;
      };
      const gateEdits = async (eds) => { const f = await Promise.all(eds.map((e) => isNewSysOrder(e["Order#"]))); return eds.filter((_, i) => f[i]); };
      try {
        let et = await search("edit_request", [{ key: "Completed", constraint_type: "greater than", value: iso }]);
        et = await gateEdits(et);
        totals.editsToday = et.length;
        et.forEach((e) => { const b = bucket(e.Assigned_Artist); if (b) b.et++; });
      } catch (e) { console.warn("[dashboard] editsToday failed:", e.message); totals.editsToday = null; }
      try {
        let em = await search("edit_request", [{ key: "Completed", constraint_type: "greater than", value: monIso }]);
        em = await gateEdits(em);
        totals.editsMonth = em.length;
        em.forEach((e) => { const b = bucket(e.Assigned_Artist); if (!b) return; b.em++; const h = editSpeedH(e); if (h != null) { b.esM[0] += h; b.esM[1]++; } });
      } catch (e) { console.warn("[dashboard] editsMonth failed:", e.message); totals.editsMonth = null; }
      /* Per-vendor edit RATE and VENDOR-ERROR rate for the month. Denominator is b.om --
         orders that vendor first-completed this month -- so the two numbers answer:
         "of the work you finished, how much came back, and how much was actually our fault?"
         Fault comes from edit_fault, which the classifier fills in automatically. */
      try {
        let opened = await search("edit_request", [{ key: "Created Date", constraint_type: "greater than", value: monIso }]);
        opened = await gateEdits(opened);
        opened.forEach((e) => { const b2 = bucket(e.Assigned_Artist); if (!b2) return; b2.eo++; if (faultOf(e) === "vendor_error") b2.ve++; });
        totals.vendorErrorsMonth = opened.filter((e) => faultOf(e) === "vendor_error").length;
        totals.editsOpenedMonth = opened.length;
        totals.faultUnlabelled = opened.filter((e) => !faultOf(e)).length;
      } catch (e) { console.warn("[dashboard] per-vendor edit rate failed:", e.message); }

      const avg = (pair) => (pair && pair[1]) ? +(pair[0] / pair[1]).toFixed(2) : null;
      const num = (a, ...ks) => { for (const k of ks) { const v = a[k]; if (v !== undefined && v !== null && v !== "") return Number(v) || 0; } return 0; };
      const artistRows = artists.map((a) => {
        const em = String(a.email || "").toLowerCase(); const b = byV[em] || {};
        const om = b.om || 0, emc = b.em || 0;
        const capDig = num(a, "max_concurrent_digitizing", "Max_concurrent_digitizing");
        const capOther = num(a, "max_concurrent_orders", "Max_concurrent_orders");
        const lastAction = a.last_action_at || a.Last_action_at || null;
        const lastUpload = a.last_upload_at || a.Last_upload_at || null;
        const idleThresh = num(a, "idle_threshold_hours", "Idle_threshold_hours"); // 0 = use global default
        return {
          email: em, contact: a.contact || "", active: a.is_active_vendor === true,
          cap: capDig + capOther, capDig, capOther,
          lastAction, lastUpload, idleThresh,
          digLoad: (b.digOp || 0) + (b.digEp || 0), otherLoad: (b.otherOp || 0) + (b.otherEp || 0),
          capabilities: Array.isArray(a.capabilities) ? a.capabilities.map((c) => String(c).toLowerCase()) : [],
          ordersPending: b.op || 0, editsPending: b.ep || 0, aging: b.ag || 0,
          editsOpenedMonth: b.eo || 0, vendorErrorsMonth: b.ve || 0,
          errorRateMonth: om ? +(((b.ve || 0) / om) * 100).toFixed(1) : null,
          orderSpeedToday: avg(b.osT), orderSpeedMonth: avg(b.osM), editSpeedMonth: avg(b.esM),
          // Edits OPENED this month against this vendor's work / orders they completed this
          // month. Same definition the vendor sees in their portal, on purpose -- two numbers
          // that disagree is an argument waiting to happen. (Was: edits *finished* / orders.)
          editPctMonth: om ? +(((b.eo || 0) / om) * 100).toFixed(1) : null,
          editsToday: b.et || 0, editsMonth: emc, ordersToday: b.ot || 0, ordersMonth: om,
        };
      }).sort((x, y) => (x.email > y.email ? 1 : -1));
      const vendors = artists.filter((a) => a.is_active_vendor === true)
        .map((a) => String(a.email || "").toLowerCase()).filter(Boolean).sort();
      // Resolve client email + team name for each order (cached, deduped across orders).
      await Promise.all(orders.map(async (ord) => {
        ord.clientEmail = await clientEmailById(ord.user);
        ord.teamName = await teamNameById(ord.teamId);
      }));
      // Unread indicator + summary box: vendor messages the admin hasn't read.
      let unreadMessages = [];
      try {
        const unread = await search(OM, [
          { key: "sender_role", constraint_type: "equals", value: "vendor" },
          { key: "read_by_admin", constraint_type: "equals", value: false }]);
        const unreadSet = new Set(unread.map((m) => String(m.order_no)));
        orders.forEach((o) => { if (unreadSet.has(String(o.orderNo))) o.unread = true; });
        const byNo = {}; orders.forEach((o) => { byNo[String(o.orderNo)] = o; });
        const seen = new Set();
        unread.forEach((m) => {
          const no = String(m.order_no); if (seen.has(no)) return; seen.add(no);
          const ord = byNo[no];
          unreadMessages.push({ orderNo: no, id: ord ? ord.id : null, vendor: ord ? (ord.assigned || ord.clientEmail || "") : "" });
        });
      } catch (e) { console.warn("[dashboard] unread scan failed:", e.message); }
      res.json({ totals, artists: artistRows, orders, vendors, unreadMessages, idleDefault: IDLE_DEFAULT_HOURS });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Push or reassign an order to a specific vendor (admin override, off-cap).
  app.post("/vendor/api/admin/assign-order", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const id = String(req.body.id || "");
      const email = String(req.body.email || "").toLowerCase().trim();
      if (!id || !email) return res.status(400).json({ ok: false, error: "Need order id + vendor email" });
      await patchOrder(id, { [F.assignedArtist]: email, [F.claimState]: CS.claimed, claimed_at: Date.now() });
      console.log(`[admin] order ${id} assigned to ${email}`);
      try { await logEvent(id, email, "admin_assigned", "admin push/reassign"); } catch {}
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // Cancel an order: stop rotation + drop from queues. Non-destructive (reversible).
  app.post("/vendor/api/admin/cancel-order", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const id = String(req.body.id || "");
      if (!id) return res.status(400).json({ ok: false, error: "Need order id" });
      await patchOrder(id, { [F.claimState]: "cancelled", Pending: false });
      console.log(`[admin] order ${id} cancelled`);
      try { await logEvent(id, "", "admin_cancelled", "admin cancelled order"); } catch {}
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  // ---- TEMP DEBUG: raw record JSON (admin only) — REMOVE after field-name check.
  // /vendor/api/admin/raw?type=artist&id=<id>  (type defaults to uploaded_image)
  /* One page of results, no pagination. search() walks the entire table (100 rows per
     HTTP call), which is fine for small constrained queries and ruinous for edit_request:
     at 1,000 edits/month that table is 12,000 rows -> 120 Bubble calls per scan. The fault
     sweep and the stats bar must never full-scan. */
  async function searchPage(type, constraints, limit = 100) {
    const q = `constraints=${encodeURIComponent(JSON.stringify(constraints))}&cursor=0&limit=${limit}`;
    const { response } = await bubble("GET", `/${type}?${q}`);
    return { rows: response.results || [], remaining: response.remaining || 0 };
  }

  /* ---- Edit fault: auto-classify + human override ---------------------------
     Two fields stored: edit_fault (answer) and fault_locked (a human set it). Config in
     ./fault-prompt.js. Forward-only: nothing before FAULT_START_ISO is ever classified. */
  const NEEDS_CLASSIFY = [
    { key: "Created Date", constraint_type: "greater than", value: FAULT_START_ISO },
    { key: "edit_fault", constraint_type: "is_empty" },
  ];
  const RECLASSIFY = [
    { key: "Created Date", constraint_type: "greater than", value: FAULT_START_ISO },
    { key: "fault_locked", constraint_type: "is_empty" },
  ];
  let _faultStats = null;

  app.post("/vendor/api/admin/set-fault", express.json(), requireAdminLogin, async (req, res) => {
    try {
      const editId = String(req.body.editId || "");
      const fault = normFault(req.body.fault);
      if (!editId || !fault) return res.status(400).json({ ok: false, error: "editId and a valid fault are required" });
      await bubble("PATCH", `/edit_request/${editId}`, { edit_fault: fault, fault_locked: "yes" });
      _faultStats = null;
      res.json({ ok: true, fault });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  async function classifyOne(er) {
    if (isLocked(er)) return { ok: true, skipped: true };
    let order = null;
    try { const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: er["Order#"] }]); order = m[0] || null; }
    catch (e) { console.warn("[fault] order lookup failed:", e.message); }
    const r = await classifyEditFault(er, order);
    if (!r.ok) return r;
    try { await bubble("PATCH", `/edit_request/${er._id}`, { edit_fault: r.fault }); }
    catch (e) { return { ok: false, error: "classified but could not save: " + e.message }; }
    _faultStats = null;
    return r;
  }

  app.post("/vendor/api/admin/classify-batch", express.json(), requireAdminLogin, async (req, res) => {
    if (!ANTHROPIC_KEY) return res.status(400).json({ ok: false, error: "ANTHROPIC_API_KEY not set on this service" });
    const limit = Math.min(Math.max(Number(req.body.limit) || 25, 1), 50);
    const constraints = req.body.mode === "reclassify" ? RECLASSIFY : NEEDS_CLASSIFY;
    try {
      const page = await searchPage("edit_request", constraints, limit);
      let done = 0; const errors = [];
      for (const er of page.rows) {
        const r = await classifyOne(er);
        if (r.ok) { if (!r.skipped) done++; } else errors.push(`${er["Order#"] || er._id}: ${r.error}`);
      }
      res.json({ ok: true, classified: done, attempted: page.rows.length, remaining: page.remaining, errors: errors.slice(0, 5) });
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  const FAULT_STATS_TTL = 15 * 60 * 1000;
  const FAULT_STATS_DAYS = 30;
  app.get("/vendor/api/admin/fault-stats", requireAdminLogin, async (_req, res) => {
    if (_faultStats && Date.now() - _faultStats.at < FAULT_STATS_TTL) return res.json(_faultStats.body);
    try {
      const win = new Date(Date.now() - FAULT_STATS_DAYS * 86400000).toISOString();
      const since = win > FAULT_START_ISO ? win : FAULT_START_ISO;
      const all = await search("edit_request", [{ key: "Created Date", constraint_type: "greater than", value: since }]);
      const labelled = all.filter((er) => faultOf(er));
      const byCode = {};
      FAULT_CODES.forEach((c) => { byCode[c] = labelled.filter((er) => faultOf(er) === c).length; });
      const body = {
        ok: true, windowDays: FAULT_STATS_DAYS, startedAt: FAULT_START_ISO,
        total: all.length, labelled: labelled.length,
        locked: all.filter((er) => isLocked(er)).length,
        pending: all.filter((er) => !faultOf(er)).length,
        model: FAULT_MODEL, keyPresent: !!ANTHROPIC_KEY, byCode,
      };
      _faultStats = { at: Date.now(), body };
      res.json(body);
    } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  });

  async function autoClassifySweep() {
    if (!ANTHROPIC_KEY) return;
    try {
      const { rows, remaining } = await searchPage("edit_request", NEEDS_CLASSIFY, SWEEP_BATCH);
      if (!rows.length) return;
      let ok = 0;
      for (const er of rows) { const r = await classifyOne(er); if (r.ok && !r.skipped) ok++; }
      console.log(`[fault-sweep] classified ${ok}/${rows.length} edit(s) with ${FAULT_MODEL}; ${remaining} waiting`);
    } catch (e) { console.warn("[fault-sweep] failed:", e.message); }
  }
  if (ANTHROPIC_KEY) {
    setTimeout(autoClassifySweep, 30 * 1000);
    setInterval(autoClassifySweep, AUTO_CLASSIFY_MIN * 60 * 1000);
  } else {
    console.warn("[fault] ANTHROPIC_API_KEY not set -- edit fault classification is off");
  }


  // TEMP diagnostic: surfaces exactly why completion mail might not send.
  //   /vendor/api/admin/email-test                       -> is the key present? what's the From?
  //   /vendor/api/admin/email-test?to=you@example.com    -> actually send a test, report SendGrid status+body
  //   /vendor/api/admin/email-test?orderNo=12345         -> resolve that order's client recipient (no send)
  // Remove before launch alongside the raw route.
  app.get("/vendor/api/admin/email-test", requireAdminLogin, async (req, res) => {
    const out = { keyPresent: !!SENDGRID_KEY, from: MAIL_FROM_EMAIL, bcc: MAIL_BCC };
    try {
      const orderNo = String(req.query.orderNo || "").trim();
      if (orderNo) {
        const rows = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: orderNo }]);
        const o = rows[0];
        if (!o) { out.recipientLookup = "order not found"; return res.json(out); }
        let to = (o.Email && String(o.Email).trim()) ? String(o.Email).trim() : "";
        out.orderEmailField = o.Email || "(blank)";
        if (!to && o.User) {
          try {
            const u = await bubble("GET", `/user/${o.User}`).then((r) => r.response);
            to = u && u.authentication && u.authentication.email && u.authentication.email.email ? u.authentication.email.email : "";
            out.resolvedFromUser = to || "(nested authentication.email.email was empty)";
          } catch (e) { out.userLookupError = e.message; }
        }
        out.wouldSendTo = to || "(none — email would be skipped)";
        return res.json(out);
      }
      const to = String(req.query.to || "").trim();
      if (!to) { out.note = "Pass ?to=email to send a test, or ?orderNo=# to check recipient resolution."; return res.json(out); }
      if (!SENDGRID_KEY) { out.result = "SENDGRID_API_KEY is not set on this service — that's why nothing sends."; return res.json(out); }
      const payload = {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: MAIL_FROM_EMAIL, name: MAIL_FROM_NAME },
        subject: "PrintReadyArt email test",
        content: [{ type: "text/plain", value: "This is a PrintReadyArt SendGrid test. If you received this, completion email is configured correctly." }],
      };
      const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method: "POST", headers: { Authorization: `Bearer ${SENDGRID_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      out.sendGridStatus = r.status;
      out.sendGridBody = await r.text();
      out.interpretation = (r.status >= 200 && r.status < 300)
        ? "Accepted by SendGrid. Check the inbox (and spam) for " + to + "."
        : (r.status === 401 ? "401 = API key invalid or lacks Mail Send permission."
          : (r.status === 403 ? "403 = sender identity not verified. Verify " + MAIL_FROM_EMAIL + " (or its domain) in SendGrid > Sender Authentication."
            : "Non-2xx from SendGrid — see sendGridBody."));
      return res.json(out);
    } catch (e) { out.error = e.message; return res.status(500).json(out); }
  });

  app.get("/vendor/api/admin/raw", requireAdminLogin, async (req, res) => {
    try {
      // Editor labels != Data API type names. Alias the names we keep mistyping so the
      // debug route resolves regardless of casing/pluralization.
      const TYPE_ALIAS = {
        new_orders: "New_Order", new_order: "New_Order", "New_Orders": "New_Order",
        order_messages: "order_message", edit_requests: "edit_request",
        artists: "artist", users: "user", teams: "team",
      };
      const raw = String(req.query.type || "uploaded_image");
      const type = TYPE_ALIAS[raw] || raw;
      const id = String(req.query.id || "");
      // No id -> list a few rows so we can discover the real field keys.
      if (!id) {
        // Optional field filter so you can find specific records, e.g.
        //   raw?type=New_Order&find=Order%23&is=DIG201F22AQ
        const constraints = [];
        if (req.query.find && req.query.is)
          constraints.push({ key: String(req.query.find), constraint_type: "equals", value: String(req.query.is) });
        const lim = Math.min(Math.max(Number(req.query.limit) || 5, 1), 20);
        const q = `constraints=${encodeURIComponent(JSON.stringify(constraints))}&limit=${lim}`;
        const rows = await bubble("GET", `/${type}?${q}`).then(r => r.response.results || []);
        return res.type("json").send(JSON.stringify({ type, count: rows.length, sample: rows }, null, 2));
      }
      const rec = await bubble("GET", `/${type}/${id}`).then(r => r.response);
      res.type("json").send(JSON.stringify(rec, null, 2));
    } catch (e) { res.status(500).json({ error: e.message }); }
  });



  // ---- PAGES (served HTML) -------------------------------------------------
  app.get("/vendor/login", (_req, res) => res.type("html").send(LOGIN_HTML));
  app.get("/vendor", requireVendor, (_req, res) => res.type("html").send(PORTAL_HTML));
  app.get("/vendor/admin", requireAdminLogin, (_req, res) => res.type("html").send(ADMIN_HTML));
  app.get("/vendor/admin/controls", requireAdminLogin, (_req, res) => res.type("html").send(CONTROLS_HTML));
  app.get("/vendor/admin/orders", requireAdminLogin, (_req, res) => res.type("html").send(ADMIN_ORDERS_HTML));
}

/* ----------------------------- HTML PAGES ---------------------------------- */
const LOGIN_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Vendor Login</title><style>
body{font-family:system-ui,sans-serif;background:#f4f6fa;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:320px}
h1{font-size:20px;margin:0 0 20px}input{width:100%;padding:10px;margin:6px 0;border:1px solid #cbd5e1;border-radius:8px;box-sizing:border-box}
button{width:100%;padding:11px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-size:15px;cursor:pointer;margin-top:8px}
.err{color:#dc2626;font-size:13px;min-height:18px}.muted{color:#64748b;font-size:12px;margin-top:14px;text-align:center}
</style></head><body><div class=card>
<h1>PrintReadyArt — Vendor Login</h1>
<div id=loginView>
<input id=email placeholder=Email autocomplete=username>
<input id=password type=password placeholder=Password autocomplete=current-password>
<button onclick=doLogin()>Log in</button>
<div class=err id=err></div></div>
<div id=changeView style=display:none>
<p style=font-size:14px>Set a new password to continue.</p>
<input id=newpw type=password placeholder="New password (8+ chars)">
<input id=newpw2 type=password placeholder="Confirm new password">
<button onclick=doChange()>Set password</button>
<div class=err id=err2></div></div>
<div class=muted>Trouble logging in? Contact your admin.</div>
</div><script>
async function doLogin(){
  err.textContent="";
  const r=await fetch('/vendor/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:email.value,password:password.value})});
  const d=await r.json();
  if(!d.ok){err.textContent=d.error||"Login failed";return;}
  if(d.isAdmin){location.href='/vendor/admin';return;}
  if(d.mustChange){loginView.style.display='none';changeView.style.display='block';return;}
  location.href='/vendor';
}
async function doChange(){
  err2.textContent="";
  if(newpw.value!==newpw2.value){err2.textContent="Passwords don't match";return;}
  const r=await fetch('/vendor/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({newPassword:newpw.value})});
  const d=await r.json();
  if(!d.ok){err2.textContent=d.error||"Failed";return;}
  location.href='/vendor';
}
addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
</script></body></html>`;

const CONTROLS_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin Controls</title><style>
body{font-family:system-ui,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
header{background:#0f172a;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
header a{color:#93c5fd;text-decoration:none;margin-left:14px;font-size:14px}
.wrap{max-width:1050px;margin:20px auto;padding:0 16px;overflow-x:auto}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th,td{padding:10px 12px;text-align:center;border-bottom:1px solid #eef2f6;font-size:14px}
th{background:#f1f5f9;color:#334155;font-weight:700;font-size:13px;white-space:nowrap}
th.vh,td.vh{text-align:left;min-width:180px}
.vemail{font-weight:600}.vsub{color:#94a3b8;font-size:12px}
tr.warnrow{background:#fef2f2}tr.warnrow td{border-top:1px solid #fecaca}
.warnmsg{color:#b91c1c;font-size:11px;font-weight:600;margin-top:3px}.nomail{color:#b91c1c}
td input[type=checkbox]{width:18px;height:18px;cursor:pointer}
input[type=number]{width:58px;padding:5px;border:1px solid #cbd5e1;border-radius:6px}
button{border:0;border-radius:8px;padding:7px 12px;font-weight:600;cursor:pointer}
.addbtn{background:#e2e8f0;color:#0f172a}.logout{background:rgba(255,255,255,.2);color:#fff}
.tagadd{padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;width:170px}
.saved{font-size:13px;margin-left:10px}
.switch{position:relative;display:inline-block;width:42px;height:24px}
.switch input{display:none}.slider{position:absolute;cursor:pointer;inset:0;background:#cbd5e1;border-radius:999px;transition:.2s}
.slider:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:#16a34a}.switch input:checked+.slider:before{transform:translateX(18px)}
</style></head><body>
<header><div><b>Admin Controls — Vendor Capabilities</b><a href="/vendor/admin">Vendor logins</a><a href="/vendor/admin/orders">Orders dashboard</a></div>
<button class=logout onclick="logout()">Log out</button></header>
<div class=wrap><div id=grid class=vsub>Loading&hellip;</div></div>
<script>
const COLS_KNOWN=[['vector','Vector'],['separations','Separations'],['digitizing','Digitizing'],['ofm','ofm'],['pfx','pfx'],['digital_printing','Digital (DTF/DTG)']];
let vendors=[],columns=[];
async function load(){
  try{const r=await fetch('/vendor/api/admin/vendor-controls');vendors=await r.json();buildColumns();render();}
  catch(e){document.getElementById('grid').textContent='Failed to load vendors.';}
}
function buildColumns(){
  const tags=[];COLS_KNOWN.forEach(function(c){tags.push(c[0]);});
  vendors.forEach(function(v){(v.capabilities||[]).forEach(function(t){t=String(t).toLowerCase();if(tags.indexOf(t)<0)tags.push(t);});});
  columns=tags.map(function(t){const k=COLS_KNOWN.find(function(c){return c[0]===t;});return {tag:t,label:k?k[1]:t};});
}
function render(){
  const grid=document.getElementById('grid');
  if(!Array.isArray(vendors)||!vendors.length){grid.textContent='No vendors found.';return;}
  let head='<tr><th class=vh>Vendor</th>';
  columns.forEach(function(c){head+='<th>'+c.label+'</th>';});
  head+='<th>Active</th><th>Max digitizing</th><th>Max other</th><th>Idle limit (h)</th></tr>';
  let rows='';
  vendors.forEach(function(v,i){
    const caps=new Set((v.capabilities||[]).map(function(c){return String(c).toLowerCase();}));
    // An active vendor can't actually receive work if they have no email (system finds
    // vendors only by email), no capabilities, or BOTH caps zero/blank. Flag it loudly.
    var md=v.maxDigitizing,mo=v.maxOther;
    var bothEmpty=!((md!==''&&md!=null&&Number(md)>0)||(mo!==''&&mo!=null&&Number(mo)>0));
    var problems=[];
    if(v.active&&!(v.email&&String(v.email).trim()))problems.push('no email \\u2014 cannot be found');
    if(v.active&&caps.size===0)problems.push('no capabilities');
    if(v.active&&bothEmpty)problems.push('both maxes 0/blank');
    var warn=problems.length?' warnrow':'';
    rows+='<tr data-i="'+i+'" class="'+warn.trim()+'"><td class=vh><div class=vemail>'+(v.email||'<span class=nomail>(no email)</span>')+'</div><div class=vsub>'+(v.contact||'')+'</div>'+
      (problems.length?'<div class=warnmsg>\\u26A0 Active but can\\'t claim: '+problems.join('; ')+'</div>':'')+'</td>';
    columns.forEach(function(c){rows+='<td><input type=checkbox data-cap="'+c.tag+'" '+(caps.has(c.tag)?'checked':'')+'></td>';});
    rows+='<td><label class=switch><input type=checkbox class=active '+(v.active?'checked':'')+'><span class=slider></span></label></td>';
    rows+='<td><input type=number class=maxdig min=0 value="'+((v.maxDigitizing===0||v.maxDigitizing)?v.maxDigitizing:'')+'"></td>';
    rows+='<td><input type=number class=maxother min=0 value="'+((v.maxOther===0||v.maxOther)?v.maxOther:'')+'"></td>';
    rows+='<td><input type=number class=idleh min=0 step=0.5 placeholder="default" value="'+((v.idleThreshold===0||v.idleThreshold)?v.idleThreshold:'')+'" title="Hours of inactivity before this vendor\\'s claimed orders return to the pool. Blank = global default."></td></tr>';
  });
  grid.innerHTML='<table>'+head+rows+'</table><div style=margin-top:14px><input id=newcap class=tagadd placeholder="add capability column"> <button class=addbtn onclick="addCol()">Add column</button> <span id=status class=saved></span></div>';
  grid.querySelector('table').addEventListener('change',function(e){const tr=e.target.closest('tr[data-i]');if(!tr)return;if(e.target.matches&&e.target.matches('input[type=checkbox][data-cap]'))enforceHierarchy(tr,e.target);saveRow(tr);});
}
function capBox(tr,tag){return tr.querySelector('input[type=checkbox][data-cap="'+tag+'"]');}
function enforceHierarchy(tr,el){
  var tag=el.getAttribute('data-cap');
  function set(t,val){var c=capBox(tr,t);if(c)c.checked=val;}
  if(el.checked){
    if(tag==='separations')set('vector',true);
    if(tag==='ofm'||tag==='pfx')set('digitizing',true);
  }else{
    if(tag==='vector')set('separations',false);
    if(tag==='digitizing'){set('ofm',false);set('pfx',false);}
  }
}
function addCol(){
  const inp=document.getElementById('newcap');const raw=inp.value.trim();const t=raw.toLowerCase().replace(/\s+/g,'_');
  if(!t){return;}
  if(columns.find(function(c){return c.tag===t;})){inp.value='';return;}
  columns.push({tag:t,label:raw});inp.value='';render();
}
async function saveRow(tr){
  const i=tr.getAttribute('data-i');const v=vendors[i];
  const capabilities=[].slice.call(tr.querySelectorAll('input[type=checkbox][data-cap]')).filter(function(c){return c.checked;}).map(function(c){return c.getAttribute('data-cap');});
  const active=tr.querySelector('.active').checked;
  const maxDigitizing=tr.querySelector('.maxdig').value;
  const maxOther=tr.querySelector('.maxother').value;
  const idleThreshold=tr.querySelector('.idleh').value;
  const status=document.getElementById('status');status.textContent='Saving\u2026';status.style.color='#64748b';
  try{
    const r=await fetch('/vendor/api/admin/vendor-controls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:v.id,capabilities:capabilities,maxDigitizing:maxDigitizing,maxOther:maxOther,idleThreshold:idleThreshold,active:active})});
    const j=await r.json();
    v.capabilities=capabilities;v.active=active;v.maxDigitizing=maxDigitizing;v.maxOther=maxOther;v.idleThreshold=idleThreshold;
    status.textContent=j.ok?('Saved '+(v.email||'')+' \u2713'):('Error: '+(j.error||'failed'));
    status.style.color=j.ok?'#16a34a':'#dc2626';
  }catch(e){status.textContent='Error saving';status.style.color='#dc2626';}
  setTimeout(function(){status.textContent='';},2500);
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
load();
</script></body></html>`;

const ADMIN_ORDERS_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Orders Dashboard</title><style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
header{background:#0f172a;color:#fff;padding:0 20px;height:56px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:20}
header a{color:#93c5fd;text-decoration:none;margin-left:14px;font-size:14px}
.logout{background:rgba(255,255,255,.18);color:#fff;border:0;border-radius:8px;padding:7px 12px;font-size:13px;font-weight:600;cursor:pointer}
.wrap{max-width:1180px;margin:16px auto;padding:0 16px}
.tabs{display:flex;gap:6px;margin-bottom:14px}
.tab{background:#e2e8f0;color:#334155;border:0;border-radius:8px 8px 0 0;padding:9px 20px;font-weight:700;cursor:pointer;font-size:14px}
.tab.active{background:#fff;color:#0f172a;box-shadow:0 -2px 0 #2563eb inset}
.toppanels{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.totalpanel{background:#fff;border-radius:12px;padding:16px 20px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:300px}
.kpistrip{display:grid;grid-template-columns:repeat(auto-fit,minmax(116px,1fr));gap:10px;margin-bottom:10px}
.kpi{background:#fff;border:1px solid #eef2f6;border-radius:10px;padding:11px 13px}
.kpi .kn{font-size:22px;font-weight:800;color:#0f172a;line-height:1.1}
.kpi .kl{font-size:12px;color:#64748b;margin-top:3px}
.kpi.alert{background:#fef2f2;border-color:#fecaca}.kpi.alert .kn{color:#dc2626}.kpi.alert .kl{color:#b91c1c}
.kpi.good{background:#f0fdf4;border-color:#bbf7d0}.kpi.good .kn{color:#16a34a}.kpi.good .kl{color:#15803d}
.kpi.clickk{cursor:pointer}.kpi.clickk:hover{filter:brightness(.98)}
.mini.m-editreq{background:#fde68a;color:#92400e}
.mini.m-review{background:#fecaca;color:#991b1b}
.reviewbox{margin:10px 0;padding:12px 14px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px}
.reviewbox .tmpl-label{color:#991b1b}
.rvlist{margin:6px 0;padding-left:18px;font-size:13px;color:#7f1d1d}
.rvlist li{margin:2px 0}
.rvprev{display:block;max-width:100%;border:1px solid #e5e7eb;border-radius:6px;margin:8px 0;background:#fff}
.rvactions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.rvapprove{background:#16a34a;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
.rvapprove:hover{background:#15803d}
.rvreject{background:#fff;color:#b91c1c;border:1px solid #fecaca;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
.rvreject:hover{background:#fef2f2}
.chiprow{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.chip2{font-size:12px;background:#f1f5f9;color:#475569;padding:5px 11px;border-radius:999px}.chip2 b{color:#0f172a;font-weight:700}
.chip2.click{cursor:pointer}.chip2.click:hover{filter:brightness(.97)}
.chip2.alert{background:#fee2e2;color:#b91c1c}.chip2.alert b{color:#b91c1c}
#msgbox:not(:empty){background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:12px 16px;margin-bottom:14px}
.msgboxhead{font-size:14px;font-weight:800;color:#1e40af;margin-bottom:8px}
.msgboxrow{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;color:#1e3a8a}
.msgboxrow:hover{background:#dbeafe}.msgboxrow.off{cursor:default;color:#64748b;font-weight:500}
.msgboxgo{margin-left:auto;font-size:12px;color:#2563eb;font-weight:700}.msgboxrow.off .msgboxgo{color:#94a3b8}
.totalpanel h3{color:#2563eb;margin:0 0 8px;font-size:18px}
.totalpanel .r{font-size:15px;font-weight:700;margin:5px 0}.totalpanel .r span{font-weight:800}
.tp-red{color:#dc2626}.tp-orange{color:#d97706}.tp-click{cursor:pointer}.tp-click:hover{text-decoration:underline}
.tiles{display:flex;flex-wrap:wrap;gap:10px;align-content:flex-start;flex:1}
.tile{background:#fff;border-radius:10px;padding:11px 15px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:96px}
.tile .n{font-size:20px;font-weight:800}.tile .l{font-size:12px;color:#64748b}.tile.warn .n{color:#dc2626}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:#fff;border:1px solid #eef2f6;border-radius:10px;padding:10px 12px;margin-bottom:12px}
.toolbar label{font-size:12px;color:#64748b;display:flex;align-items:center;gap:5px}
select,input{padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px}
.list{background:#fff;border:1px solid #eef2f6;border-radius:12px;overflow:hidden}
.row{display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid #f1f5f9;cursor:pointer;transition:background .12s}
.row:last-child{border-bottom:0}.row:hover{background:#f8fafc}.row.multi{border-left:3px solid #dc2626}
.rthumb{width:36px;height:36px;border-radius:8px;object-fit:cover;border:1px solid #e2e8f0;background:#f1f5f9;flex:none}
.rthumb.ph{display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:16px}
.rmain{flex:1;min-width:0}.rtitle{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rsub{font-size:12px;color:#64748b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rasg{width:150px;flex:none;font-size:13px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rright{flex:none;display:flex;align-items:center;gap:8px}
.mini{font-size:10px;font-weight:700;padding:1px 7px;border-radius:999px;margin-left:5px}
.m-sep{background:#fef3c7;color:#92400e}.m-rush{background:#fee2e2;color:#b91c1c}.m-multi{background:#fee2e2;color:#b91c1c}.m-un{background:#fef3c7;color:#92400e}
.timer{display:inline-flex;align-items:center;font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;white-space:nowrap}
.t-green{background:#dcfce7;color:#15803d}.t-orange{background:#ffedd5;color:#c2410c}.t-red{background:#fee2e2;color:#b91c1c}
.chev{color:#cbd5e1;font-size:18px;font-style:normal}
.osub{color:#64748b;font-size:12px}.muted{color:#94a3b8;font-size:14px;padding:24px;text-align:center}
.statwrap{overflow-x:auto}
table.stats{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:13px}
table.stats th,table.stats td{padding:8px 10px;border-bottom:1px solid #eef2f6;text-align:center;white-space:nowrap}
table.stats th{background:#f1f5f9;color:#334155;font-weight:700}table.stats td.vn,table.stats th.vn{text-align:left}
table.stats td.g,table.stats td.o,table.stats td.r{font-weight:700}.g{color:#16a34a}.o{color:#d97706}.r{color:#dc2626}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.on{background:#16a34a}.off{background:#cbd5e1}
.apill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;background:#f1f5f9;color:#475569}
.apill.pill-green{background:#dcfce7;color:#15803d}
.apill.pill-amber{background:#fef3c7;color:#92400e}
.apill.pill-red{background:#fee2e2;color:#b91c1c}
#backdrop{position:fixed;inset:0;background:rgba(15,23,42,.45);opacity:0;pointer-events:none;transition:opacity .2s;z-index:40}
#backdrop.open{opacity:1;pointer-events:auto}
#panel{position:fixed;top:0;right:0;height:100%;width:460px;max-width:100%;background:#fff;transform:translateX(100%);transition:transform .25s ease;z-index:50;overflow-y:auto}
#panel.open{transform:translateX(0)}@media(max-width:560px){#panel{width:100%}}
.phead{position:sticky;top:0;background:#fff;border-bottom:1px solid #eef2f6;padding:16px 18px;display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.ptitle{font-size:18px;font-weight:700}.peyebrow{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;font-weight:600}
.pclose{background:#f1f5f9;border:0;border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:15px;color:#475569;flex:none}
.pbody{padding:16px 18px 28px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;margin:0 5px 6px 0}
.b-type{background:#eef2ff;color:#3730a3}.b-rush{background:#fee2e2;color:#b91c1c}.b-sep{background:#fef3c7;color:#92400e}
.pthumb{width:100%;max-height:200px;object-fit:contain;border-radius:8px;border:1px solid #e2e8f0;margin:6px 0;cursor:pointer}
.specline{font-size:13px;color:#334155;margin:4px 0}.specline b{color:#0f172a}
.multibanner{display:flex;gap:8px;background:#fee2e2;color:#991b1b;border-radius:8px;padding:9px 12px;font-size:13px;font-weight:700;margin-bottom:12px}
.eligbox{margin-top:10px;padding:10px 12px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px}
.editreqbox{margin:10px 0;padding:10px 12px;background:#fffbeb;border:1px solid #fde68a;border-radius:8px}
.faultbar{display:flex;flex-wrap:wrap;align-items:center;gap:14px;background:#fff;border:1px solid #e6ebf1;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}
.fbstat{color:#64748b}
.faultbox{margin-top:10px;padding-top:10px;border-top:1px dashed #fcd34d}
.faultrow{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:6px}
.faultpill{font-size:12px;font-weight:700;padding:3px 9px;border-radius:999px}
.faultpill.f-vendor_error{background:#fee2e2;color:#b91c1c}
.faultpill.f-client_change{background:#dcfce7;color:#15803d}
.faultpill.f-unclear{background:#e2e8f0;color:#475569}
.faultby{font-size:12px;color:#94a3b8}
.faultbtn{font-size:12px;font-weight:600;padding:5px 10px;border-radius:7px;border:1px solid #d8dee6;background:#fff;color:#334155;cursor:pointer}
.faultbtn:hover{background:#f8fafc}
.faultbtn.on{background:#0f172a;border-color:#0f172a;color:#fff}
.faultai{font-size:12px;font-weight:600;padding:5px 10px;border-radius:7px;border:1px solid #c7d2fe;background:#eef2ff;color:#4338ca;cursor:pointer}
.faultai:hover{background:#e0e7ff}
.faultmsg{font-size:12px;font-weight:600}
.aisugg{margin-top:8px;padding:8px 10px;background:#eef2ff;border:1px solid #e0e7ff;border-radius:7px;font-size:12.5px;color:#3730a3}
.airat{margin-top:3px;color:#4c51bf;font-weight:400}
.editreqbox .tmpl-label{color:#92400e}
.eref{display:inline-block;margin-right:8px;color:#2563eb;font-size:13px;text-decoration:underline}
.msgwrap{margin-top:16px;border-top:1px solid #eef2f6;padding-top:14px}
.thread{max-height:240px;overflow-y:auto;background:#f8fafc;border:1px solid #eef2f6;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:8px}
.msgempty{color:#94a3b8;font-size:13px;text-align:center;padding:14px}
.bub{max-width:82%;padding:7px 10px;border-radius:12px;font-size:13px}
.bub.me{align-self:flex-end;background:#2563eb;color:#fff;border-bottom-right-radius:3px}
.bub.them{align-self:flex-start;background:#fff;border:1px solid #e2e8f0;color:#0f172a;border-bottom-left-radius:3px}
.bubmeta{font-size:10px;opacity:.7;margin-bottom:2px}
.bubtext{white-space:pre-wrap;word-break:break-word}
.msgrow{display:flex;gap:8px;margin-top:8px}
.msgrow textarea{flex:1;padding:8px;border:1px solid #cbd5e1;border-radius:8px;font-size:13px;font-family:inherit;resize:vertical}
.msgsend{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:0 16px;font-size:13px;font-weight:600;cursor:pointer}
.mini.msgnew{background:#2563eb;color:#fff}
.uploadwrap{margin-top:16px;border-top:1px solid #eef2f6;padding-top:14px}.uploadwrap .tag{font-size:12px;color:#64748b;display:block;margin-bottom:4px}
.upload{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
.cancelbtn{background:#fee2e2;color:#b91c1c;border:0;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
</style></head><body>
<header><div><b>Orders Dashboard</b><a href="/vendor/admin">Vendor logins</a><a href="/vendor/admin/controls">Vendor controls</a></div>
<button class=logout onclick="logout()">Log out</button></header>
<div class=wrap>
<div class=tabs><button class="tab active" id=tabOrders onclick="showTab('orders')">Orders</button><button class=tab id=tabVendors onclick="showTab('vendors')">By Vendor</button></div>
<div id=paneOrders>
  <div id=kpis></div>
  <div id=faultbar></div>
  <div id=msgbox></div>
  <div class=toolbar>
    <label>Search <input id=fSearch type=text placeholder="Order #" oninput="setFilter()" style=width:120px></label>
    <label>Sort <select id=sortSel onchange="setSort(this.value)">
      <option value=placed>Time since placed</option><option value=held>Time held (claimed)</option><option value=vendor>Vendor</option><option value=type>Type</option><option value=multi>Multiple edits first</option></select></label>
    <label>Vendor <select id=fVendor onchange="setFilter()"><option value="">All</option></select></label>
    <label>Client <select id=fClient onchange="setFilter()"><option value="">All</option></select></label>
    <label>State <select id=fState onchange="setFilter()"><option value="">All</option><option value=unassigned>Unassigned</option><option value=assigned>Assigned</option></select></label>
    <label>Type <select id=fType onchange="setFilter()"><option value="">All</option></select></label>
    <label><input type=checkbox id=fMulti onchange="setFilter()"> Multiple edits only</label>
    <label><input type=checkbox id=fEdit onchange="setFilter()"> Edit requests only</label>
    <span id=lcount class=osub></span>
  </div>
  <div id=orders class=list></div>
</div>
<div id=paneVendors style=display:none><div class=statwrap><div id=stats></div></div></div>
</div>
<div id=backdrop onclick="closeDetail()"></div>
<div id=panel></div>
<script>
let DATA={vendors:[],orders:[],artists:[],totals:{}},byId={},panelOpenId=null;
let sortBy='placed',fltVendor='',fltState='',fltType='',fltMulti=false,fltEdit=false,fltSearch='',fltClient='',fltReview=false;
function fmtH(h){if(h==null)return '\\u2013';if(h>=48)return (h/24).toFixed(1)+'d';return h+'h';}
function completionClass(h){if(h==null)return 't-green';if(h>14)return 't-red';if(h>=6)return 't-orange';return 't-green';}
function claimAgeClass(h){if(h==null)return 't-green';if(h>3)return 't-red';if(h>=1.5)return 't-orange';return 't-green';}
function spdClass(v){if(v==null)return '';if(v<5)return 'g';if(v<=10)return 'o';return 'r';}
function pctClass(v){if(v==null)return '';if(v<10)return 'g';if(v<=15)return 'o';return 'r';}
function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return c==='<'?'&lt;':c==='>'?'&gt;':'&amp;';});}
function shortUser(u){u=String(u);return (u.indexOf('@')>=0||u.length<=18)?u:(u.slice(0,14)+'\\u2026');}
function phThumb(){return '<div class="rthumb ph">\\u25A1</div>';}
function showTab(t){
  document.getElementById('paneOrders').style.display=t==='orders'?'block':'none';
  document.getElementById('paneVendors').style.display=t==='vendors'?'block':'none';
  document.getElementById('tabOrders').classList.toggle('active',t==='orders');
  document.getElementById('tabVendors').classList.toggle('active',t==='vendors');
}
async function load(){
  try{const r=await fetch('/vendor/api/admin/dashboard');DATA=await r.json();}
  catch(e){document.getElementById('orders').innerHTML='<div class=muted>Failed to load.</div>';return;}
  byId={};(DATA.orders||[]).forEach(function(o){byId[o.id]=o;});
  populateFilters();renderKpis();renderMsgBox();renderList();renderStats();
  if(panelOpenId&&byId[panelOpenId])fillPanel(byId[panelOpenId]);
}
function renderMsgBox(){
  var box=document.getElementById('msgbox');var list=DATA.unreadMessages||[];
  if(!list.length){box.innerHTML='';return;}
  var rows=list.map(function(m){
    var label='Order #'+esc(m.orderNo)+(m.vendor?' \\u00b7 '+esc(m.vendor):'');
    return m.id
      ? '<div class=msgboxrow onclick="openDetail(\\''+m.id+'\\')">\\uD83D\\uDCAC '+label+' <span class=msgboxgo>Open \\u203A</span></div>'
      : '<div class="msgboxrow off">\\uD83D\\uDCAC '+label+' <span class=msgboxgo>(order not in list)</span></div>';
  }).join('');
  box.innerHTML='<div class=msgboxhead>\\uD83D\\uDCAC Unread messages ('+list.length+')</div>'+rows;
}
function renderKpis(){
  var t=DATA.totals||{};var v=function(n){return n==null?'0':n;};
  var un=(DATA.orders||[]).filter(function(o){return !o.assigned;});
  var oldest=0;un.forEach(function(o){if(o.createdHours!=null&&o.createdHours>oldest)oldest=o.createdHours;});
  var oldestStr=un.length?fmtH(oldest):'\\u2013';
  function kpi(n,l,cls,oc){return '<div class="kpi'+(cls?' '+cls:'')+(oc?' clickk':'')+'"'+(oc?' onclick="'+oc+'"':'')+'><div class=kn>'+n+'</div><div class=kl>'+l+'</div></div>';}
  var strip=kpi(v(t.aging),'Aging',t.aging?'alert':'')+
    kpi(v(t.unassigned),'Unassigned',t.unassigned?'alert':'')+
    kpi(v(t.pending),'Pending')+
    kpi(v(t.openEdits),'Edits pending','',t.openEdits?'filterEdits()':'')+
    kpi(v(t.needsReview),'Needs review',t.needsReview?'alert':'',t.needsReview?'filterReview()':'')+
    kpi(oldestStr,'Oldest unclaimed')+
    kpi(v(t.completedToday),'Done today')+
    kpi(v(t.editsToday),'Edits today')+
    kpi(v(t.completedMonth),'Done / month',t.completedMonth?'good':'');
  var chips='<span class=chip2>Vector <b>'+v(t.vector)+'</b></span>'+
    '<span class=chip2>Digitizing <b>'+v(t.digitizing)+'</b></span>'+
    '<span class=chip2>Digital <b>'+v(t.digital)+'</b></span>'+
    '<span class=chip2>Other <b>'+v(t.other)+'</b></span>'+
    '<span class="chip2 click'+(t.multiEdit?' alert':'')+'" onclick="filterMulti()">Multiple edits <b>'+v(t.multiEdit)+'</b></span>';
  document.getElementById('kpis').innerHTML='<div class=kpistrip>'+strip+'</div><div class=chiprow>'+chips+'</div>';
}
function populateFilters(){
  var vsel=document.getElementById('fVendor');var cur=vsel.value;
  var vs=(DATA.vendors||[]).slice();(DATA.orders||[]).forEach(function(o){if(o.assigned&&vs.indexOf(o.assigned)<0)vs.push(o.assigned);});
  vsel.innerHTML='<option value="">All</option>'+vs.map(function(e){return '<option value="'+e+'">'+esc(shortUser(e))+'</option>';}).join('');vsel.value=cur;
  var tsel=document.getElementById('fType');var curt=tsel.value;var types=[];
  (DATA.orders||[]).forEach(function(o){var tp=o.type||'(none)';if(types.indexOf(tp)<0)types.push(tp);});
  tsel.innerHTML='<option value="">All</option>'+types.map(function(tp){return '<option value="'+esc(tp)+'">'+esc(tp)+'</option>';}).join('');tsel.value=curt;
  var csel=document.getElementById('fClient');var curc=csel.value;var clients=[];
  (DATA.orders||[]).forEach(function(o){var c=o.clientEmail||'';if(c&&clients.indexOf(c)<0)clients.push(c);});
  clients.sort();
  csel.innerHTML='<option value="">All</option>'+clients.map(function(c){return '<option value="'+esc(c)+'">'+esc(c)+'</option>';}).join('');csel.value=curc;
}
function setSort(v){sortBy=v;renderList();}
function setFilter(){fltReview=false;fltVendor=document.getElementById('fVendor').value;fltState=document.getElementById('fState').value;fltType=document.getElementById('fType').value;fltMulti=document.getElementById('fMulti').checked;fltEdit=document.getElementById('fEdit').checked;fltSearch=document.getElementById('fSearch').value.trim().toLowerCase();fltClient=document.getElementById('fClient').value;renderList();}
function filterMulti(){document.getElementById('fMulti').checked=true;showTab('orders');setFilter();}
function filterEdits(){document.getElementById('fEdit').checked=true;showTab('orders');setFilter();}
function filterReview(){fltReview=true;showTab('orders');renderList();}
function applyFilter(arr){return arr.filter(function(o){
  if(fltReview)return o.inReview;
  if(fltVendor&&o.assigned!==fltVendor)return false;
  if(fltClient&&(o.clientEmail||'')!==fltClient)return false;
  if(fltState==='unassigned'&&o.assigned)return false;
  if(fltState==='assigned'&&!o.assigned)return false;
  if(fltType&&(o.type||'(none)')!==fltType)return false;
  if(fltMulti&&!o.multiEdit)return false;
  if(fltEdit&&!o.hasEdit)return false;
  if(fltSearch&&String(o.orderNo||'').toLowerCase().indexOf(fltSearch)<0)return false;
  return true;});}
function applySort(arr){arr.sort(function(a,b){
  if(sortBy==='placed')return (b.createdHours||0)-(a.createdHours||0);
  if(sortBy==='vendor')return String(a.assigned).localeCompare(String(b.assigned));
  if(sortBy==='type')return String(a.type).localeCompare(String(b.type));
  if(sortBy==='multi'){var m=(b.multiEdit?1:0)-(a.multiEdit?1:0);if(m)return m;}
  var av=a.claimedHours!=null?a.claimedHours:-1,bv=b.claimedHours!=null?b.claimedHours:-1;return bv-av;});return arr;}
function renderList(){
  var arr=applySort(applyFilter((DATA.orders||[]).slice()));
  document.getElementById('lcount').textContent=arr.length+' shown';
  if(!arr.length){document.getElementById('orders').innerHTML='<div class=muted>No orders match.</div>';return;}
  document.getElementById('orders').innerHTML=arr.map(rowHtml).join('');
}
function rowHtml(o){
  var thumb=o.thumb?'<img class=rthumb src="'+o.thumb+'" onerror="this.outerHTML=phThumb()">':phThumb();
  var assigned=o.assigned?esc(shortUser(o.assigned)):'<span class="mini m-un">Unassigned</span>';
  var marks=(o.unread?'<span class="mini msgnew">\\uD83D\\uDCAC New</span>':'')+(o.inReview?'<span class="mini m-review">\\u26A0 Review</span>':'')+(o.hasEdit?'<span class="mini m-editreq">\\u270E Edit</span>':'')+(o.separations==='yes'?'<span class="mini m-sep">Sep</span>':'')+(o.rush==='yes'?'<span class="mini m-rush">Rush</span>':'')+(o.multiEdit?'<span class="mini m-multi">\\u26A0 Multi-edit</span>':'');
  var pill=(o.claimedHours!=null)
    ? '<div class="timer '+completionClass(o.claimedHours)+'" title="Time held since claimed">'+fmtH(o.claimedHours)+'</div>'
    : '<div class="timer '+claimAgeClass(o.createdHours)+'" title="Unclaimed \\u2014 time since placed">\\u231B '+fmtH(o.createdHours)+'</div>';
  return '<div class="row'+(o.multiEdit?' multi':'')+'" onclick="openDetail(\\''+o.id+'\\')">'+thumb+
    '<div class=rmain><div class=rtitle>Order '+esc(o.orderNo||o.id)+marks+'</div><div class=rsub>'+esc(o.type||'(no type)')+' \\u00b7 '+esc(shortUser(o.clientEmail||o.user||'?'))+'</div></div>'+
    '<div class=rasg>'+assigned+'</div><div class=rright>'+pill+'<i class=chev>\\u203A</i></div></div>';
}
function fmtAgo(ts){
  if(!ts)return '\\u2013';
  var t=new Date(ts).getTime();if(isNaN(t))return '\\u2013';
  var m=Math.floor((Date.now()-t)/60000);
  if(m<1)return 'just now';if(m<60)return m+'m ago';
  var h=Math.floor(m/60);if(h<24)return h+'h ago';
  var d=Math.floor(h/24);return d+'d ago';
}
// Green if active, amber as they approach their idle threshold, red once past it (idle).
function activityClass(ts,threshHours){
  if(!ts)return '';
  var t=new Date(ts).getTime();if(isNaN(t))return '';
  var h=(Date.now()-t)/3600000;var lim=threshHours>0?threshHours:(DATA.idleDefault||5);
  if(h>lim)return 'pill-red';if(h>lim*0.6)return 'pill-amber';return 'pill-green';
}
function renderStats(){
  var a=DATA.artists||[];if(!a.length){document.getElementById('stats').textContent='No vendors.';return;}
  var cols=[['ordersPending','Orders Pending'],['editsPending','Edits Pending'],['aging','Aging Orders'],
    ['orderSpeedToday','Order Speed Today','spd'],['orderSpeedMonth','Order Speed Month','spd'],['editSpeedMonth','Edit Speed Month','spd'],
    ['editPctMonth','Edit % Month','pct'],['errorRateMonth','Vendor Error % Month','pct'],['vendorErrorsMonth','Vendor Errors Month'],
    ['editsToday','Edits Finished Today'],['editsMonth','Edits Finished Month'],['ordersToday','Orders Finished Today'],['ordersMonth','Orders Finished Month']];
  var h='<table class=stats><tr><th class=vn>By Artist</th><th>Last active</th><th>Last upload</th><th>Idle limit</th>';cols.forEach(function(c){h+='<th>'+c[1]+'</th>';});h+='</tr>';
  a.forEach(function(v){
    var actCls=activityClass(v.lastAction,v.idleThresh);
    var lim=(v.idleThresh>0?v.idleThresh:(DATA.idleDefault||5))+'h'+(v.idleThresh>0?'':'*');
    h+='<tr><td class=vn><span class="dot '+(v.active?'on':'off')+'"></span>'+esc(v.contact||v.email||'(no email)')+'<div class=osub>'+esc(v.email||'')+'</div></td>'+
      '<td><span class="apill '+actCls+'">'+fmtAgo(v.lastAction)+'</span></td>'+
      '<td>'+fmtAgo(v.lastUpload)+'</td>'+
      '<td title="'+(v.idleThresh>0?'per-vendor override':'* global default')+'">'+lim+'</td>';
    cols.forEach(function(c){var val=v[c[0]];var cls=c[2]==='spd'?spdClass(val):(c[2]==='pct'?pctClass(val):'');var disp=(val==null||val==='')?'\\u2013':(c[2]==='pct'?val+'%':val);h+='<td class="'+cls+'">'+disp+'</td>';});h+='</tr>';});
  h+='</table><div class=osub style="margin-top:6px">* using global default of '+(DATA.idleDefault||5)+'h. Orders held by a vendor idle past their limit return to the shared pool automatically.</div>';document.getElementById('stats').innerHTML=h;
}
function eligibleFor(o){
  var req=o.reqCaps||[];
  var dig=(o.type==='Digitizing');
  return (DATA.artists||[]).filter(function(a){
    if(!a.active)return false;
    var caps=(a.capabilities||[]).map(function(c){return String(c).toLowerCase();});
    for(var i=0;i<req.length;i++){if(caps.indexOf(req[i])<0)return false;}
    return true;
  }).map(function(a){
    var load=dig?(a.digLoad||0):(a.otherLoad||0);
    var cap=dig?a.capDig:a.capOther;cap=(cap==null||cap==='')?null:Number(cap);
    return {email:a.email,contact:a.contact,load:load,cap:cap,bucket:(dig?'digitizing':'other'),under:(cap!=null&&load<cap)};
  });
}
// Small fault scoreboard. Auto-classifies in the background; a human override locks a row.
// After editing fault-prompt.js, use "Re-classify" to re-run every unlocked edit.
async function renderFaultBar(){
  var el=document.getElementById('faultbar');if(!el)return;
  try{
    const r=await fetch('/vendor/api/admin/fault-stats');const d=await r.json();
    if(!d.ok){el.innerHTML='';return;}
    var n=(d.pending>25?25:d.pending);
    var btn=d.keyPresent?'<button class=faultai onclick="classifyBatch()">\\u2728 Classify '+n+' now</button>':'<span class=faultby>ANTHROPIC_API_KEY not set</span>';
    var codes=d.byCode||{};
    el.innerHTML='<div class=faultbar><b>Edit fault</b>'+
      '<span class=fbstat title="Rolling '+d.windowDays+'-day window. Edits before go-live are never classified.">'+d.labelled+' / '+d.total+' classified</span>'+
      '<span class=fbstat>since '+shortDate(d.startedAt)+'</span>'+
      '<span class=fbstat title="Human overrides that the classifier will not touch.">'+d.locked+' locked</span>'+
      '<span class=fbstat><span class=faultpill f-vendor_error>'+(codes.vendor_error||0)+'</span> <span class=faultpill f-client_change>'+(codes.client_change||0)+'</span> <span class=faultpill f-unclear>'+(codes.unclear||0)+'</span></span>'+
      (d.pending?'<span class=fbstat>'+d.pending+' pending</span>':'')+
      (d.pending?btn:'')+(d.keyPresent&&d.labelled?'<button class=faultghost onclick="reclassifyAll()" title="Re-run every unlocked edit through the current prompt. Locked rows untouched.">Re-classify</button>':'')+'<span id=fbMsg class=faultmsg></span></div>';
  }catch(e){el.innerHTML='';}
}
async function classifyBatch(){
  var m=document.getElementById('fbMsg');if(m){m.style.color='#64748b';m.textContent='Classifying\\u2026';}
  try{
    const r=await fetch('/vendor/api/admin/classify-batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit:25})});
    const d=await r.json();
    if(d.ok){if(m){m.style.color='#16a34a';m.textContent='Classified '+d.classified+' of '+d.attempted+(d.remaining?' \\u00b7 '+d.remaining+' left':'');}renderFaultBar();load();}
    else if(m){m.style.color='#dc2626';m.textContent=d.error||'Failed';}
  }catch(e){if(m){m.style.color='#dc2626';m.textContent='Failed';}}
}
async function reclassifyAll(){
  if(!confirm('Re-run the classifier on all UNLOCKED edits with the current prompt? Rows you set by hand are untouched.'))return;
  var m=document.getElementById('fbMsg');if(m){m.style.color='#64748b';m.textContent='Re-classifying\\u2026';}
  try{
    const r=await fetch('/vendor/api/admin/classify-batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit:50,mode:'reclassify'})});
    const d=await r.json();
    if(d.ok){if(m){m.style.color='#16a34a';m.textContent='Re-classified '+d.classified+(d.remaining?' \\u00b7 '+d.remaining+' left (click again)':'');}renderFaultBar();load();}
    else if(m){m.style.color='#dc2626';m.textContent=d.error||'Failed';}
  }catch(e){if(m){m.style.color='#dc2626';m.textContent='Failed';}}
}
function shortDate(iso){if(!iso)return '\\u2013';var d=new Date(iso);return isNaN(d)?'\\u2013':d.toLocaleDateString([],{month:'short',day:'numeric'});}
function faultLabel(f){return f==='vendor_error'?'Our mistake':(f==='client_change'?'Client change':(f==='unclear'?'Unclear':''));}
function faultBoxHtml(er){
  if(!er.id)return '';
  var cur=er.fault||'';
  var who=cur?(er.locked?'set by you':'auto-classified'):'awaiting classification';
  var chosen=cur?'<span class="faultpill f-'+cur+'">'+faultLabel(cur)+'</span><span class=faultby>'+who+'</span>'
                :'<span class=faultby>'+who+'</span>';
  var btns=['vendor_error','client_change','unclear'].map(function(f){
    return '<button class="faultbtn'+(cur===f?' on':'')+'" onclick="setFault(\\''+er.id+'\\',\\''+f+'\\')">'+faultLabel(f)+'</button>';
  }).join('');
  return '<div class=faultbox><div class=tmpl-label>Fault</div>'+
    '<div class=faultrow>'+chosen+'</div>'+
    '<div class=faultrow><span class=faultby>Override:</span>'+btns+'</div>'+
    '<div id=faultMsg class=faultmsg></div></div>';
}
async function setFault(editId,fault){
  var m=document.getElementById('faultMsg');if(m){m.style.color='#64748b';m.textContent='Saving\\u2026';}
  try{
    const r=await fetch('/vendor/api/admin/set-fault',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({editId:editId,fault:fault})});
    const d=await r.json();
    if(d.ok){if(m){m.style.color='#16a34a';m.textContent='Saved \\u0026 locked.';}load();renderFaultBar();}
    else if(m){m.style.color='#dc2626';m.textContent=d.error||'Could not save';}
  }catch(e){if(m){m.style.color='#dc2626';m.textContent='Could not save';}}
}

function vendList(arr){
  if(!arr.length)return '<div style=font-size:13px;color:#94a3b8>none</div>';
  return arr.map(function(v){return '<div class=specline>'+esc(v.contact||v.email)+' <span style=color:#94a3b8>('+v.load+(v.cap!=null?'/'+v.cap:'')+' load)</span></div>';}).join('');
}
function fillPanel(o){
  var claimed=(o.state==='claimed');
  var badges=(o.type?'<span class="badge b-type">'+esc(o.type)+'</span>':'')+(o.rush==='yes'?'<span class="badge b-rush">RUSH</span>':'')+(o.separations==='yes'?'<span class="badge b-sep">SEPARATIONS</span>':'');
  var multi=o.multiEdit?'<div class=multibanner>\\u26A0 This order has had multiple edits</div>':'';
  var thumb=o.thumb?'<img class=pthumb src="'+o.thumb+'" onclick="window.open(\\''+o.thumb+'\\',\\'_blank\\')" onerror="this.style.display=\\'none\\'">':'';
  var opts=(DATA.vendors||[]).map(function(e){return '<option value="'+e+'"'+(e===o.assigned?' selected':'')+'>'+esc(e)+'</option>';}).join('');
  var statusBlock;
  if(claimed){
    statusBlock='<div class=specline><b>Status:</b> Claimed</div>'+
      '<div class=specline><b>Assigned:</b> '+esc(o.assigned||'?')+'</div>'+
      '<div class=specline><b>Claimed:</b> '+(o.claimedHours!=null?fmtH(o.claimedHours)+' ago':'\\u2013')+'</div>';
  }else{
    var el=eligibleFor(o);var avail=el.filter(function(v){return v.under;}),fullv=el.filter(function(v){return !v.under;});
    statusBlock='<div class=specline><b>Status:</b> <span style=color:#b45309;font-weight:700>Unclaimed</span> \\u00b7 in the shared pool, waiting '+fmtH(o.createdHours)+' since placed</div>'+
      '<div class=eligbox><div class=tmpl-label>Available to claim now'+(o.reqCaps&&o.reqCaps.length?' \\u00b7 needs: '+esc(o.reqCaps.join(', ')):'')+'</div>'+vendList(avail)+
      (fullv.length?'<div class=tmpl-label style=margin-top:8px>Eligible but at capacity</div>'+vendList(fullv):'')+
      (!el.length?'<div style=font-size:13px;color:#b91c1c;margin-top:4px>No eligible vendor has these capabilities \\u2014 assign manually or add a capable vendor.</div>':'')+'</div>';
  }
  var msgBlock=claimed
    ? '<div class=msgwrap><div class=tmpl-label>Messages with '+esc(o.assigned||'vendor')+'</div><div id=thread class=thread>Loading\\u2026</div><div class=msgrow><textarea id=msgInput rows=2 placeholder="Write a message\\u2026"></textarea><button class=msgsend onclick="sendMsg(\\''+esc(o.orderNo)+'\\')">Send</button></div></div>'
    : '<div class=msgwrap><div class=tmpl-label>Messages</div><div class=msgempty style=text-align:left>Messaging opens once a vendor claims this order.</div></div>';
  var editReq='';
  if(o.hasEdit&&o.edit){
    var er=o.edit;
    var refs=(er.refs&&er.refs.length)?er.refs.map(function(r){return '<a href="'+r.url+'" target=_blank class=eref>'+esc(r.label)+'</a>';}).join(' '):'';
    var erAgo=er.created?fmtH(+(((Date.now()-new Date(er.created).getTime())/3600000)).toFixed(2))+' ago':'';
    editReq='<div class=editreqbox><div class=tmpl-label>\\u270E Edit requested by client</div>'+
      (er.changes?'<div class=specline><b>Changes:</b> '+esc(er.changes)+'</div>':'')+
      (er.reason?'<div class=specline><b>Reason:</b> '+esc(er.reason)+'</div>':'')+
      (er.artist?'<div class=specline><b>Working it:</b> '+esc(shortUser(er.artist))+'</div>':'')+
      (erAgo?'<div class=specline><b>Requested:</b> '+esc(erAgo)+'</div>':'')+
      (refs?'<div class=specline><b>References:</b> '+refs+'</div>':'')+
      faultBoxHtml(er)+'</div>';
  }
  var reviewBox='';
  if(o.inReview){
    var reasons=(o.reviewReasons||'').split(' | ').filter(function(x){return x;});
    var rlist=reasons.length?('<ul class=rvlist>'+reasons.map(function(x){return '<li>'+esc(x)+'</li>';}).join('')+'</ul>'):'<div class=specline>Flagged for manual review.</div>';
    var prev=o.reviewPreview?('<img src="'+esc(o.reviewPreview)+'" class=rvprev alt="stitch preview">'):'';
    reviewBox='<div class=reviewbox><div class=tmpl-label>\\u26A0 Flagged by automated QA</div>'+
      (o.assigned?'<div class=specline><b>Vendor:</b> '+esc(shortUser(o.assigned))+'</div>':'')+
      rlist+prev+
      '<div class=rvactions>'+
      '<button class=rvapprove onclick="reviewApprove(\\''+o.id+'\\')">\\u2713 Approve &amp; complete</button>'+
      '<button class=rvreject onclick="reviewReject(\\''+o.id+'\\')">\\u2717 Reject with notes</button>'+
      '</div><div id=rvMsg class=faultmsg></div></div>';
  }
  panel.innerHTML='<div class=phead><div><div class=ptitle>Order '+esc(o.orderNo||o.id)+'</div><div class=peyebrow>'+esc(o.type||'')+(o.ref?' \\u00b7 PO '+esc(o.ref):'')+'</div></div><button class=pclose onclick="closeDetail()">\\u2715</button></div>'+
    '<div class=pbody>'+multi+'<div>'+badges+'</div>'+thumb+reviewBox+editReq+
    '<div class=specline><b>Client:</b> '+esc(o.clientEmail||o.user||'?')+'</div>'+
    '<div class=specline><b>Team:</b> '+esc(o.teamName||'\\u2013')+'</div>'+statusBlock+
    '<div class=specline><b>Created:</b> '+(o.createdHours!=null?fmtH(o.createdHours)+' ago':'\\u2013')+'</div>'+
    '<div class=uploadwrap><span class=tag>Assign / reassign to vendor</span><div style=display:flex;gap:8px;flex-wrap:wrap><select id=asgSel>'+(o.assigned?'':'<option value="">choose\\u2026</option>')+opts+'</select>'+
    '<button class=upload onclick="assignOrder(\\''+o.id+'\\')">'+(o.assigned?'Reassign':'Push')+'</button></div>'+
    '<div style=margin-top:14px><button class=cancelbtn onclick="cancelOrder(\\''+o.id+'\\')">Cancel order</button></div><span id=pmsg class=tag style=display:block;margin-top:8px></span></div>'+
    msgBlock+'</div>';
}
var msgPoll=null,msgOrderNo=null;
function openThread(orderNo){msgOrderNo=orderNo;loadThread();markThreadRead();if(msgPoll)clearInterval(msgPoll);msgPoll=setInterval(function(){if(msgOrderNo)loadThread();},9000);}
function stopThread(){if(msgPoll)clearInterval(msgPoll);msgPoll=null;msgOrderNo=null;}
function loadThread(){if(!msgOrderNo)return;fetch('/vendor/api/messages?orderNo='+encodeURIComponent(msgOrderNo)).then(function(r){return r.json();}).then(function(d){renderThread(d.messages||[]);}).catch(function(){});}
function renderThread(msgs){var el=document.getElementById('thread');if(!el)return;
  if(!msgs.length){el.innerHTML='<div class=msgempty>No messages yet.</div>';return;}
  el.innerHTML=msgs.map(function(m){var mine=m.role==='admin';return '<div class="bub '+(mine?'me':'them')+'"><div class=bubmeta>'+(mine?'You':esc(m.email||'Vendor'))+' \\u00b7 '+msgTime(m.at)+'</div><div class=bubtext>'+esc(m.body)+'</div></div>';}).join('');
  el.scrollTop=el.scrollHeight;}
function sendMsg(orderNo){var ta=document.getElementById('msgInput');if(!ta)return;var body=ta.value.trim();if(!body)return;ta.value='';
  fetch('/vendor/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderNo:orderNo,body:body})}).then(function(r){return r.json();}).then(function(){loadThread();}).catch(function(){});}
function markThreadRead(){if(!msgOrderNo)return;fetch('/vendor/api/messages/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderNo:msgOrderNo})}).catch(function(){});}
function msgTime(at){if(!at)return'';var d=new Date(at);if(isNaN(d))return'';return d.toLocaleString([],{month:'numeric',day:'numeric',hour:'numeric',minute:'2-digit'});}
function openDetail(id){var o=byId[id];if(!o)return;panelOpenId=id;fillPanel(o);panel.classList.add('open');backdrop.classList.add('open');if(o.state==='claimed')openThread(o.orderNo);}
function closeDetail(){stopThread();panelOpenId=null;panel.classList.remove('open');backdrop.classList.remove('open');load();}
function assignOrder(id){
  var email=document.getElementById('asgSel').value;var msg=document.getElementById('pmsg');
  if(!email){msg.textContent='Pick a vendor';msg.style.color='#dc2626';return;}
  msg.textContent='Assigning\\u2026';msg.style.color='#64748b';
  fetch('/vendor/api/admin/assign-order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,email:email})}).then(function(r){return r.json();}).then(function(j){if(j.ok){closeDetail();}else{msg.textContent='Error: '+(j.error||'failed');msg.style.color='#dc2626';}});
}
function cancelOrder(id){
  if(!confirm('Cancel this order? It stops rotating and leaves all queues.'))return;
  var msg=document.getElementById('pmsg');msg.textContent='Cancelling\\u2026';msg.style.color='#64748b';
  fetch('/vendor/api/admin/cancel-order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})}).then(function(r){return r.json();}).then(function(j){if(j.ok){closeDetail();}else{msg.textContent='Error: '+(j.error||'failed');msg.style.color='#dc2626';}});
}
async function reviewApprove(id){
  if(!confirm('Approve this order and mark it complete? The client will be emailed that it is ready.'))return;
  var m=document.getElementById('rvMsg');if(m){m.style.color='#64748b';m.textContent='Approving\\u2026';}
  try{
    const r=await fetch('/vendor/api/admin/review-approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    const j=await r.json();
    if(j.ok){closeDetail();load();}else if(m){m.style.color='#dc2626';m.textContent=j.error||'Failed';}
  }catch(e){if(m){m.style.color='#dc2626';m.textContent='Failed';}}
}
async function reviewReject(id){
  var notes=prompt('Reject and send back to the vendor. Enter notes explaining what to fix:');
  if(notes==null)return;
  notes=notes.trim();
  if(!notes){alert('Notes are required to reject.');return;}
  var m=document.getElementById('rvMsg');if(m){m.style.color='#64748b';m.textContent='Rejecting\\u2026';}
  try{
    const r=await fetch('/vendor/api/admin/review-reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,notes:notes})});
    const j=await r.json();
    if(j.ok){closeDetail();load();}else if(m){m.style.color='#dc2626';m.textContent=j.error||'Failed';}
  }catch(e){if(m){m.style.color='#dc2626';m.textContent='Failed';}}
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
load();
// Fetched once per page open, NOT in the 30s poll: the stats scan is the single most
// expensive query in this system, and polling it would burn workflow units for a number
// that barely moves. Re-rendered explicitly after any fault action.
renderFaultBar();
setInterval(function(){if(!panelOpenId)load();},30000);
</script></body></html>`;

const PORTAL_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>My Orders</title><style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
.banner{background:#fef3c7;color:#92400e;padding:8px 16px;font-size:13px;text-align:center}.banner a{color:#92400e}
header{background:#0f172a;color:#fff;padding:0 18px;height:56px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:20}
header h1{font-size:16px;margin:0;font-weight:600}
.chips{display:flex;gap:7px;align-items:center}
.chip{font-size:12px;font-weight:600;padding:4px 11px;border-radius:999px;background:rgba(255,255,255,.12);color:#cbd5e1}
.chip.info{background:#dbeafe;color:#1e40af}.chip.danger{background:#fee2e2;color:#b91c1c}.chip.zero{opacity:.45}
.chip.slots{background:#1e293b;color:#cbd5e1}.chip.slots.full{background:#fee2e2;color:#b91c1c}
.logout{background:rgba(255,255,255,.18);color:#fff;border:0;border-radius:8px;padding:7px 12px;font-size:13px;font-weight:600;cursor:pointer;margin-left:6px}
main{max-width:880px;margin:18px auto;padding:0 16px}
.glabel{font-size:12px;color:#94a3b8;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin:20px 4px 8px;display:flex;align-items:center;gap:8px}
.glabel .gc{background:#e2e8f0;color:#475569;border-radius:999px;padding:1px 8px;font-size:11px}
.list{background:#fff;border:1px solid #eef2f6;border-radius:12px;overflow:hidden}
.row{display:flex;align-items:center;gap:12px;padding:11px 14px;border-bottom:1px solid #f1f5f9;cursor:pointer;transition:background .12s}
.row:last-child{border-bottom:0}.row:hover{background:#f8fafc}
.row.av{border-left:3px solid #2563eb}.row.ed{border-left:3px solid #dc2626}.row.nopick{cursor:default}.row.nopick:hover{background:#fff}
.row.locked{border-left:3px solid #e2e8f0;opacity:.6}
.nextpill{font-size:11px;font-weight:700;color:#64748b;background:#f1f5f9;border:1px solid #e2e8f0;padding:4px 10px;border-radius:999px;white-space:nowrap}
.rthumb{width:38px;height:38px;border-radius:8px;object-fit:cover;border:1px solid #e2e8f0;background:#f1f5f9;flex:none}
.rthumb.ph{display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:17px}
.rmain{flex:1;min-width:0}
.rtitle{font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rsub{font-size:12px;color:#64748b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rtype{font-size:13px;color:#64748b;width:92px;flex:none}
.rright{flex:none;display:flex;align-items:center;gap:8px}
.mini{font-size:10px;font-weight:700;padding:1px 7px;border-radius:999px;margin-left:5px;vertical-align:1px}
.m-new{background:#dbeafe;color:#1e40af}.m-sep{background:#fef3c7;color:#92400e}.m-multi{background:#fee2e2;color:#b91c1c}
.timer{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;white-space:nowrap}
.t-green{background:#dcfce7;color:#15803d}.t-orange{background:#ffedd5;color:#c2410c}.t-red{background:#fee2e2;color:#b91c1c}
.claim{background:#16a34a;color:#fff;border:0;border-radius:8px;padding:6px 13px;font-size:13px;font-weight:600;cursor:pointer}
.chev{color:#cbd5e1;font-size:18px;font-style:normal}
.muted{color:#94a3b8;font-size:14px;padding:30px;text-align:center}
#backdrop{position:fixed;inset:0;background:rgba(15,23,42,.45);opacity:0;pointer-events:none;transition:opacity .2s;z-index:40}
#backdrop.open{opacity:1;pointer-events:auto}
#panel{position:fixed;top:0;right:0;height:100%;width:480px;max-width:100%;background:#fff;transform:translateX(100%);transition:transform .25s ease;z-index:50;overflow-y:auto}
#panel.open{transform:translateX(0)}
@media(max-width:560px){#panel{width:100%}}
.phead{position:sticky;top:0;background:#fff;border-bottom:1px solid #eef2f6;padding:16px 18px;display:flex;justify-content:space-between;align-items:flex-start;gap:12px;z-index:2}
.ptitle{font-size:18px;font-weight:700;line-height:1.2}
.peyebrow{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;font-weight:600}
.pclose{background:#f1f5f9;border:0;border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:15px;color:#475569;flex:none}
.pbody{padding:16px 18px 28px}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;margin:0 5px 6px 0;letter-spacing:.02em}
.b-type{background:#eef2ff;color:#3730a3}.b-rush{background:#fee2e2;color:#b91c1c}.b-sep{background:#fef3c7;color:#92400e}.b-edit{background:#fde68a;color:#92400e}
.pthumb{width:100%;max-height:220px;object-fit:contain;border-radius:8px;border:1px solid #e2e8f0;background:#fff;margin:6px 0 4px;cursor:pointer}
.spec{background:#f0f9ff;border:1px solid #e0f2fe;border-radius:8px;padding:10px 12px;margin-top:10px}
.spec-label{font-size:11px;color:#0369a1;font-weight:700;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
.specline{font-size:13px;color:#334155;margin:3px 0}.specline b{color:#0f172a}
.notes{font-size:13px;color:#334155;background:#f8fafc;border-left:3px solid #cbd5e1;padding:8px 11px;border-radius:4px;margin-top:10px;white-space:pre-wrap}
.tmpl{margin-top:12px}.tmpl-label{font-size:11px;color:#64748b;font-weight:700;margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
.link{background:#eef2f6;color:#334155;text-decoration:none;display:inline-flex;align-items:center;gap:5px;margin:0 5px 5px 0;padding:6px 11px;border-radius:7px;font-size:13px;font-weight:500}
.tmpl .link{background:#dbeafe;color:#1e40af}
.editbox{margin-top:12px;padding:12px;background:#fef2f2;border:1px solid #fecaca;border-radius:8px}.editbox .link{background:#fee2e2;color:#991b1b}
.multibanner{display:flex;align-items:center;gap:8px;background:#fee2e2;color:#991b1b;border-radius:8px;padding:9px 12px;font-size:13px;font-weight:700;margin-bottom:12px}
.limbar{background:#fff;border:1px solid #e6ebf1;border-radius:12px;padding:12px 16px;margin-bottom:16px}
.limbar.allfull{border-color:#fecaca;background:#fff7f7}
.limline{font-size:14px;color:#0f172a}
.limnote{font-size:12.5px;color:#64748b;margin-top:4px}
.limmetrics{display:flex;flex-wrap:wrap;gap:22px;margin:12px 0 2px}
.limmetrics .met{display:flex;flex-direction:column;line-height:1.25}
.limmetrics .met b{font-size:19px;font-weight:800;color:#0f172a}
.limmetrics .met span{font-size:11.5px;color:#64748b;margin-top:2px}
.limmax{margin-top:10px;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:8px;padding:9px 12px;font-size:13px;font-weight:600}
.mailme{display:flex;align-items:center;gap:10px;margin:14px 0 4px;flex-wrap:wrap}
.mailbtn{background:#f1f5f9;color:#334155;border:1px solid #dbe3ea;border-radius:8px;padding:8px 13px;font-size:13px;font-weight:600;cursor:pointer}
.mailbtn:hover{background:#e9eef4}
.mailbtn:disabled{opacity:.6;cursor:default}
.mailmsg{font-size:12.5px;font-weight:600}
.uploadwrap{margin-top:16px;border-top:1px solid #eef2f6;padding-top:14px}
.uploadwrap .tag{font-size:12px;color:#64748b;display:block;margin-top:10px;margin-bottom:3px}
.msgwrap{margin-top:16px;border-top:1px solid #eef2f6;padding-top:14px}
.thread{max-height:240px;overflow-y:auto;background:#f8fafc;border:1px solid #eef2f6;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:8px}
.msgempty{color:#94a3b8;font-size:13px;text-align:center;padding:14px}
.bub{max-width:82%;padding:7px 10px;border-radius:12px;font-size:13px}
.bub.me{align-self:flex-end;background:#2563eb;color:#fff;border-bottom-right-radius:3px}
.bub.them{align-self:flex-start;background:#fff;border:1px solid #e2e8f0;color:#0f172a;border-bottom-left-radius:3px}
.bubmeta{font-size:10px;opacity:.7;margin-bottom:2px}
.bubtext{white-space:pre-wrap;word-break:break-word}
.msgrow{display:flex;gap:8px;margin-top:8px}
.msgrow textarea{flex:1;padding:8px;border:1px solid #cbd5e1;border-radius:8px;font-size:13px;font-family:inherit;resize:vertical}
.msgsend{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:0 16px;font-size:13px;font-weight:600;cursor:pointer}
.mini.msgnew{background:#2563eb;color:#fff}
.uploadwrap input{padding:7px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px}
.upload{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 16px;font-size:14px;font-weight:600;cursor:pointer;margin-top:12px}
.paction{margin-top:16px}
</style></head><body>
<div id=banner class=banner style=display:none></div>
<header><h1>PrintReadyArt &mdash; My Orders</h1><div class=chips id=chips></div></header>
<main id=main></main>
<div id=backdrop onclick="closeDetail()"></div>
<div id=panel></div>
<script>
let data={},byId={},panelOpenId=null;
async function load(){
  const r=await fetch('/vendor/api/orders');
  if(r.status===302||r.redirected){location.href='/vendor/login';return;}
  data=await r.json();
  byId={};
  (data.claimable||[]).forEach(function(o){o._state='available';o._key=o.id;byId[o._key]=o;});
  (data.claimed||[]).forEach(function(o){o._state='progress';o._key=o.id;byId[o._key]=o;});
  (data.edits||[]).forEach(function(o){o._state='edit';o._key='e:'+((o.edit&&o.edit.reqId)||o.orderNo);byId[o._key]=o;});
  if(data.actingAs){banner.style.display='block';banner.innerHTML='Viewing as '+esc(data.actingAs)+' \\u2014 <a href="#" onclick="stopRunAs();return false">exit</a>';}
  renderChips();renderList();
  if(panelOpenId&&byId[panelOpenId])fillPanel(byId[panelOpenId]);
}
function renderChips(){
  var av=(data.claimable||[]).filter(function(o){return !o.locked;}).length,ed=(data.edits||[]).length;
  var dig=(data.digLoad!=null?data.digLoad:0)+'/'+(data.capDig!=null?data.capDig:0);
  var oth=(data.otherLoad!=null?data.otherLoad:0)+'/'+(data.capOther!=null?data.capOther:0);
  var digFull=!data.underDig,othFull=!data.underOther;
  var mt=(data.monthlyTimer!=null&&data.monthlyTimer!=='')?(data.monthlyTimer+'h'):'\\u2013';
  var met=(data.monthlyEditTimer!=null&&data.monthlyEditTimer!=='')?(data.monthlyEditTimer+'h'):'\\u2013';
  chips.innerHTML=
    (ed?'<span class="chip danger">'+ed+' edit'+(ed===1?'':'s')+'</span>':'')+
    (av?'<span class="chip info">'+av+' ready to claim</span>':'')+
    '<span class=chip title="Avg turnaround this month \\u2014 orders (claim\\u2192done) / edits">Month \\u23F1 '+esc(String(mt))+' ord / '+esc(String(met))+' edit</span>'+
    '<span class="chip slots'+(digFull?' full':'')+'" title="Digitizing slots in use">Digitizing '+dig+'</span>'+
    '<span class="chip slots'+(othFull?' full':'')+'" title="Vector + Digital (DTF/DTG) slots in use">Vector + DTF '+oth+'</span>'+
    '<button class=logout onclick=logout()>Log out</button>';
}
function renderList(){
  var av=(data.claimable||[]).slice(),pr=(data.claimed||[]).slice(),ed=(data.edits||[]).slice();
  pr.sort(function(a,b){return new Date(a.claimedAt||0)-new Date(b.claimedAt||0);});
  ed.sort(function(a,b){var m=(b.multiEdit?1:0)-(a.multiEdit?1:0);if(m)return m;return new Date((a.edit&&a.edit.created)||0)-new Date((b.edit&&b.edit.created)||0);});
  var html=groupHtml('Edit requests',ed,'edit')+groupHtml('Available to claim',av,'available')+groupHtml('In progress',pr,'progress');
  main.innerHTML=limitsBarHtml()+(html||'<div class=muted>Nothing in your queue right now.</div>');
}
// Limits + maxed-out messaging. Deliberately BUCKET-AWARE: with two independent caps a
// vendor can be full on digitizing and wide open on vector/DTF, so a blanket
// "you are maxed out" would be wrong half the time and would suppress claims we want.
function limitsBarHtml(){
  var dl=data.digLoad!=null?data.digLoad:0,dc=data.capDig!=null?data.capDig:0;
  var ol=data.otherLoad!=null?data.otherLoad:0,oc=data.capOther!=null?data.capOther:0;
  var digFull=!data.underDig,othFull=!data.underOther;
  var line='<div class=limline><b>Your limits</b> \\u00b7 Digitizing '+dl+'/'+dc+' \\u00b7 Vector + DTF '+ol+'/'+oc+'</div>';
  // Live monthly metrics. "Edit request rate" is deliberately NOT called an error rate:
  // it counts every edit, including client change-requests that were never our fault.
  var mt=(data.monthlyTimer!=null&&data.monthlyTimer!=='')?(data.monthlyTimer+'h'):'\\u2013';
  var met=(data.monthlyEditTimer!=null&&data.monthlyEditTimer!=='')?(data.monthlyEditTimer+'h'):'\\u2013';
  var ep=(data.editPct!=null)?(data.editPct+'%'):'\\u2013';
  var mets='<div class=limmetrics>'+
    '<span class=met title="Average hours from claiming an order to completing it, this month"><b>'+esc(String(mt))+'</b><span>New order speed</span></span>'+
    '<span class=met title="Average hours from an edit being requested to you resolving it, this month"><b>'+esc(String(met))+'</b><span>Edit speed</span></span>'+
    '<span class=met title="Edits opened this month on your work, divided by the orders you completed this month. Includes client change requests, which are not vendor errors."><b>'+esc(String(ep))+'</b><span>Edit request rate</span></span>'+
    '</div>';
  var note='<div class=limnote>We actively monitor turn time and edit request % to increase the number of jobs you can claim.</div>';
  var callout='';
  if(digFull&&othFull){
    callout='<div class=limmax>\\u26D4 You\\'re at both limits. Complete an order to free up a slot.</div>';
  }else if(digFull){
    callout='<div class=limmax>\\u26D4 You\\'re at your digitizing limit ('+dl+'/'+dc+'). Complete a digitizing job to claim another.'+(oc>0?' You still have '+(oc-ol)+' Vector + DTF slot'+((oc-ol)===1?'':'s')+' open.':'')+'</div>';
  }else if(othFull){
    callout='<div class=limmax>\\u26D4 You\\'re at your Vector + DTF limit ('+ol+'/'+oc+'). Complete one to claim another.'+(dc>0?' You still have '+(dc-dl)+' Digitizing slot'+((dc-dl)===1?'':'s')+' open.':'')+'</div>';
  }
  return '<div class="limbar'+((digFull&&othFull)?' allfull':'')+'">'+line+mets+note+callout+'</div>';
}
function groupHtml(label,arr,state){
  if(!arr.length)return '';
  return '<div class=glabel>'+label+' <span class=gc>'+arr.length+'</span></div><div class=list>'+arr.map(function(o){return rowHtml(o,state);}).join('')+'</div>';
}
function phThumb(){return '<div class="rthumb ph">\\u25A1</div>';}
function shortUser(u){u=String(u);return (u.indexOf('@')>=0||u.length<=16)?u:(u.slice(0,12)+'\\u2026');}
function rowHtml(o,state){
  if(state==='available'){
    if(o.locked){
      return '<div class="row av nopick locked"><div class="rthumb ph">\\u25A1</div>'+
        '<div class=rmain><div class=rtitle>Order '+esc(o.orderNo||o.id)+'</div><div class=rsub>Next in line \\u00b7 #'+(o.pos||'?')+' in the '+esc(o.type||'')+' queue</div></div>'+
        '<div class=rtype>'+esc(o.type||'')+'</div><div class=rright><span class=nextpill>Next in line</span></div></div>';
    }
    var canClaim=(o.type==='Digitizing')?data.underDig:data.underOther;
    var act=canClaim?'<button class=claim onclick="claim(\\''+o.id+'\\')">Claim</button>':'<span style=color:#94a3b8;font-size:13px>At limit</span>';
    return '<div class="row av nopick"><div class="rthumb ph">\\u25A1</div>'+
      '<div class=rmain><div class=rtitle>Order '+esc(o.orderNo||o.id)+'<span class="mini m-new">Next up</span></div><div class=rsub>Oldest '+esc(o.type||'')+' \\u2014 ready to claim</div></div>'+
      '<div class=rtype>'+esc(o.type||'')+'</div><div class=rright>'+act+'</div></div>';
  }
  var cls='row'+(state==='edit'?' ed':'');
  var thumb=o.thumb?'<img class=rthumb src="'+o.thumb+'" onerror="this.outerHTML=phThumb()">':phThumb();
  var marks='';
  if(o.unread)marks+='<span class="mini msgnew">\\uD83D\\uDCAC New</span>';
  if(o.separations==='yes')marks+='<span class="mini m-sep">Sep</span>';
  if(o.multiEdit)marks+='<span class="mini m-multi">\\u26A0 Multi-edit</span>';
  var sub=(state==='edit')?esc((o.edit&&o.edit.changes)||'Edit requested'):('Order '+esc(o.orderNo));
  var since=(state==='edit'&&o.edit)?o.edit.created:o.claimedAt;var lbl=state==='edit'?'edit requested':'claimed';
  var right=since?'<div class="timer '+timerClass(since)+'" data-since="'+since+'" data-label="'+lbl+'">'+elapsedText(lbl,since)+'</div>':'';
  return '<div class="'+cls+'" onclick="openDetail(\\''+o._key+'\\')">'+thumb+
    '<div class=rmain><div class=rtitle>Order '+esc(o.orderNo||o.id)+marks+'</div><div class=rsub>'+sub+'</div></div>'+
    '<div class=rtype>'+esc(o.type||'')+'</div><div class=rright>'+right+'<i class=chev>\\u203A</i></div></div>';
}
function specBlockHtml(o){
  var d=o.details||{};var unit=d['cm/in']||d.Unit||'';var out='';
  function rowS(label,val){return (val===''||val==null)?'':'<div class=specline><b>'+label+':</b> '+esc(String(val))+'</div>';}
  if(o.separations==='yes'){var sb=rowS('Film Size',d.FilmSizeSeps)+rowS('Art Size',d.ArtDims_Seps)+rowS('Art Placement',d.ArtPlacement_Seps)+rowS('Unit',unit);if(sb)out+='<div class=spec><div class=spec-label>Separations spec</div>'+sb+'</div>';}
  if((o.type||'').toLowerCase()==='digitizing'){
    var no=d.newOrder||{};
    // Requested size (the value the QA check measures against): Dimension + Proportional_to.
    var reqSize='';
    if(no.dimension&&no.proportionalTo){
      var axis=String(no.proportionalTo).toLowerCase()==='tall'?'tall':(String(no.proportionalTo).toLowerCase()==='wide'?'wide':String(no.proportionalTo));
      reqSize=no.dimension+'\\u2033 '+axis;
    }
    // Plain cap/flat label parsed from the Placement string.
    var pl=String(no.placement||'').toLowerCase();
    var kind=(pl.indexOf('round')>=0||pl.indexOf('hat')>=0||pl.indexOf('cap')>=0)?'Cap / Round (sew bottom-up, center-out)':((pl.indexOf('flat')>=0||pl.indexOf('left to right')>=0)?'Flat (sew left-to-right)':'');
    var db=rowS('Requested size',reqSize)+rowS('Type',kind)+rowS('Special instructions',no.specialInstructions)+rowS('Height',d.Height)+rowS('Width',d.Width)+rowS('Number of logos',unit)+rowS('3D Puff',no.puff)+rowS('Fabric content',no.fabric)+rowS('Placement',no.placement);
    if(db)out+='<div class=spec><div class=spec-label>Digitizing spec</div>'+db+'</div>';
  }
  return out;
}
function tmplBlockHtml(o){
  if(!o.team)return '';
  var tpl=[],instrParts=[];
  if(o.separations==='yes'){tpl=tpl.concat(o.team.sepTemplates||[]);if(o.team.sepInstr)instrParts.push(o.team.sepInstr);}
  if((o.type||'').toLowerCase()==='digitizing'){tpl=tpl.concat(o.team.digTemplates||[]);if(o.team.digInstr)instrParts.push(o.team.digInstr);}
  var tl=tpl.map(function(t){return '<a class=link target=_blank href="'+t.url+'">\\u2B07 '+esc(t.label)+'</a>';}).join('');
  var instr=instrParts.join('\\n\\n');var ti=instr?'<div class=notes><b>Team instructions:</b> '+esc(instr)+'</div>':'';
  return (tl||ti)?'<div class=tmpl><div class=tmpl-label>Team templates \\u0026 instructions</div>'+tl+ti+'</div>':'';
}
function editBlockHtml(o){
  if(!o.edit)return '';
  var refs=(o.edit.refs||[]).map(function(rf){return '<a class=link target=_blank href="'+rf.url+'">\\u2B07 '+esc(rf.label)+'</a>';}).join('');
  return '<div class=editbox><div class=tmpl-label style=color:#b91c1c>What the client wants changed</div>'+
    (o.edit.reason?'<div style=font-size:12px;color:#64748b;margin-bottom:4px>Reason: '+esc(o.edit.reason)+'</div>':'')+
    (o.edit.changes?'<div class=notes style=border-left-color:#dc2626;margin-top:0>'+esc(o.edit.changes)+'</div>':'<div style=font-size:12px;color:#64748b>(no note provided)</div>')+
    (refs?'<div style=margin-top:8px><div class=tmpl-label>Reference files</div>'+refs+'</div>':'')+'</div>';
}
function filesBlockHtml(o,state){
  if(!o.files||!o.files.length)return '';
  var label=state==='edit'?'Original work':'Source files';
  return '<div class=tmpl><div class=tmpl-label>'+label+'</div>'+o.files.map(function(f){return '<a class=link target=_blank href="'+f.url+'">\\u2B07 '+esc(f.label)+'</a>';}).join('')+'</div>';
}
function uploadFormHtml(o,isEdit){
  if(!o.id)return '<div class=uploadwrap><div style=font-size:13px;color:#b91c1c>Original order not found \\u2014 cannot upload a revision.</div></div>';
  var emb=(o.type||'').toLowerCase()==='digitizing';
  var embFields=emb?('<span class=tag style=color:#b45309;font-weight:600>Digitizing \\u2014 required:</span><div style=display:flex;gap:8px;flex-wrap:wrap><input id=pW type=number placeholder="Width" style=width:90px><input id=pH type=number placeholder="Height" style=width:90px><input id=pSc type=number placeholder="Stitch count" style=width:120px></div>'):'';
  return '<div class=uploadwrap>'+
    '<span class=tag>Preview JPEG (before/after):</span><input id=pPrev type=file accept="image/*">'+
    '<span class=tag>Supporting files (replaces existing):</span><input id=pSup type=file multiple>'+
    embFields+
    '<span class=tag>Number of logos (required):</span><input id=pLg type=number placeholder="# of logos" style=width:120px>'+
    '<div><button class=upload onclick="submitPanel(\\''+o.id+'\\','+emb+')">'+(isEdit?'Upload revised \\u0026 close edit':'Submit \\u0026 mark complete')+'</button></div></div>';
}
function fillPanel(o){
  var state=o._state;
  var pill='';
  var since=(state==='edit'&&o.edit)?o.edit.created:(state==='progress'?o.claimedAt:null);
  if(since){var lbl=state==='edit'?'edit requested':'claimed';pill='<div class="timer '+timerClass(since)+'" data-since="'+since+'" data-label="'+lbl+'">'+elapsedText(lbl,since)+'</div>';}
  var badges=(state==='edit'?'<span class="badge b-edit">EDIT REQUEST</span>':'')+
    (o.type?'<span class="badge b-type">'+esc(o.type)+'</span>':'')+
    (o.rush==='yes'?'<span class="badge b-rush">RUSH</span>':'')+
    (o.separations==='yes'?'<span class="badge b-sep">SEPARATIONS</span>':'');
  var multi=o.multiEdit?'<div class=multibanner>\\u26A0 This order has had multiple edits</div>':'';
  var thumb=o.thumb?'<img class=pthumb src="'+o.thumb+'" onclick="window.open(\\''+o.thumb+'\\',\\'_blank\\')" onerror="this.style.display=\\'none\\'">':'';
  var notes=o.specialInstructions?'<div class=notes><b>Special instructions:</b> '+esc(o.specialInstructions)+'</div>':'';
  var action=(state==='available')?'<div class=paction><button class=upload style=background:#16a34a onclick="claim(\\''+o.id+'\\')">Claim this order</button></div>':uploadFormHtml(o,state==='edit');
  var mailMe=(state==='available')?'':'<div class=mailme><button id=mailBtn class=mailbtn onclick="emailInstructions(\\''+o.id+'\\')">\\u2709 Email me these instructions</button><span id=mailMsg class=mailmsg></span></div>';
  panel.innerHTML='<div class=phead><div><div class=ptitle>Order '+esc(o.orderNo||'')+'</div><div class=peyebrow>'+esc(o.type||'')+'</div></div><div style=display:flex;gap:8px;align-items:center>'+pill+'<button class=pclose onclick="closeDetail()">\\u2715</button></div></div>'+
    '<div class=pbody>'+multi+'<div>'+badges+'</div>'+thumb+(state==='edit'?editBlockHtml(o):'')+notes+specBlockHtml(o)+tmplBlockHtml(o)+filesBlockHtml(o,state)+mailMe+action+(state!=='available'?msgBlockHtml(o):'')+'</div>';
}
async function emailInstructions(id){
  var b=document.getElementById('mailBtn'),m=document.getElementById('mailMsg');
  if(!b)return;
  b.disabled=true;var old=b.textContent;b.textContent='Sending\\u2026';m.textContent='';
  try{
    const r=await fetch('/vendor/api/email-instructions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id})});
    const d=await r.json();
    if(d.ok){b.textContent=old;m.style.color='#16a34a';m.textContent='Sent to '+d.sentTo;}
    else{b.textContent=old;m.style.color='#dc2626';m.textContent=d.error||'Could not send';}
  }catch(e){b.textContent=old;m.style.color='#dc2626';m.textContent='Could not send';}
  b.disabled=false;
}
function msgBlockHtml(o){
  return '<div class=msgwrap><div class=tmpl-label>Messages with PrintReadyArt</div>'+
    '<div id=thread class=thread>Loading\\u2026</div>'+
    '<div class=msgrow><textarea id=msgInput rows=2 placeholder="Write a message\\u2026"></textarea><button class=msgsend onclick="sendMsg(\\''+esc(o.orderNo)+'\\')">Send</button></div></div>';
}
var msgPoll=null,msgOrderNo=null;
function openThread(orderNo){msgOrderNo=orderNo;loadThread();markThreadRead();if(msgPoll)clearInterval(msgPoll);msgPoll=setInterval(function(){if(msgOrderNo)loadThread();},9000);}
function stopThread(){if(msgPoll)clearInterval(msgPoll);msgPoll=null;msgOrderNo=null;}
function loadThread(){if(!msgOrderNo)return;fetch('/vendor/api/messages?orderNo='+encodeURIComponent(msgOrderNo)).then(function(r){return r.json();}).then(function(d){renderThread(d.messages||[]);}).catch(function(){});}
function renderThread(msgs){var el=document.getElementById('thread');if(!el)return;
  if(!msgs.length){el.innerHTML='<div class=msgempty>No messages yet.</div>';return;}
  el.innerHTML=msgs.map(function(m){var mine=m.role==='vendor';return '<div class="bub '+(mine?'me':'them')+'"><div class=bubmeta>'+(mine?'You':'PrintReadyArt')+' \\u00b7 '+msgTime(m.at)+'</div><div class=bubtext>'+esc(m.body)+'</div></div>';}).join('');
  el.scrollTop=el.scrollHeight;}
function sendMsg(orderNo){var ta=document.getElementById('msgInput');if(!ta)return;var body=ta.value.trim();if(!body)return;ta.value='';
  fetch('/vendor/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderNo:orderNo,body:body})}).then(function(r){return r.json();}).then(function(){loadThread();}).catch(function(){});}
function markThreadRead(){if(!msgOrderNo)return;fetch('/vendor/api/messages/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderNo:msgOrderNo})}).catch(function(){});}
function msgTime(at){if(!at)return'';var d=new Date(at);if(isNaN(d))return'';return d.toLocaleString([],{month:'numeric',day:'numeric',hour:'numeric',minute:'2-digit'});}
function openDetail(key){var o=byId[key];if(!o)return;panelOpenId=key;fillPanel(o);panel.classList.add('open');backdrop.classList.add('open');if(o._state!=='available')openThread(o.orderNo);}
function closeDetail(){stopThread();panelOpenId=null;panel.classList.remove('open');backdrop.classList.remove('open');load();}
function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return c==='<'?'&lt;':c==='>'?'&gt;':'&amp;';});}
function elapsedText(lbl,since){var el=fmtElapsed(since);return '\\u23F1 '+lbl+' '+el+(el==='just now'?'':' ago');}
function fmtElapsed(since){
  if(!since)return '';
  var ms=Date.now()-new Date(since).getTime();
  if(isNaN(ms)||ms<0)return 'just now';
  var m=Math.floor(ms/60000),h=Math.floor(m/60),d=Math.floor(h/24);
  if(d>0)return d+'d '+(h%24)+'h';
  if(h>0)return h+'h '+(m%60)+'m';
  if(m>0)return m+'m';
  return 'just now';
}
function timerClass(since){
  if(!since)return 't-green';
  var h=(Date.now()-new Date(since).getTime())/3600000;
  if(isNaN(h))return 't-green';
  if(h>14)return 't-red';if(h>=6)return 't-orange';return 't-green';
}
async function claim(id){
  const r=await fetch('/vendor/api/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id})});
  const d=await r.json();
  if(!d.ok){var m=d.reason==='claim_oldest_first'?'Please claim the oldest order in line first.':(d.reason==='at_digitizing_limit'?'You\\'re at your digitizing limit \\u2014 finish a digitizing job first.':(d.reason==='at_other_limit'?'You\\'re at your vector/digital limit \\u2014 finish one first.':(d.reason||d.error||'Could not claim')));alert(m);}
  panelOpenId=null;panel.classList.remove('open');backdrop.classList.remove('open');load();
}
async function submitPanel(id,emb){
  var prev=document.getElementById('pPrev').files[0];
  var sup=document.getElementById('pSup').files;
  if(!prev&&sup.length===0){alert('Attach a preview or at least one file');return;}
  var logos=document.getElementById('pLg').value;
  if(!logos){alert('Number of logos is required');return;}
  var fd=new FormData();fd.append('orderId',id);fd.append('logos',logos);
  if(prev)fd.append('preview',prev);
  for(var i=0;i<sup.length;i++)fd.append('supporting',sup[i]);
  if(emb){var w=document.getElementById('pW').value,h=document.getElementById('pH').value,sc=document.getElementById('pSc').value;
    if(!w||!h||!sc){alert('Digitizing orders require Width, Height, and Stitch Count');return;}
    fd.append('width',w);fd.append('height',h);fd.append('stitchCount',sc);}
  var r=await fetch('/vendor/api/upload',{method:'POST',body:fd});
  var d=await r.json();
  if(!d.ok){alert(d.error||'Upload failed');return;}
  panelOpenId=null;panel.classList.remove('open');backdrop.classList.remove('open');load();
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
async function stopRunAs(){await fetch('/vendor/api/admin/stop-run-as',{method:'POST'});location.href='/vendor/admin';}
setInterval(function(){
  document.querySelectorAll('.timer[data-since]').forEach(function(el){
    var s=el.getAttribute('data-since'),lbl=el.getAttribute('data-label')||'claimed';
    el.className='timer '+timerClass(s);el.textContent=elapsedText(lbl,s);
  });
},1000);
load();
setInterval(function(){if(!panelOpenId)load();},30000);
</script></body></html>`;

const ADMIN_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Vendor Admin</title><style>
body{font-family:system-ui,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
header{background:#0f172a;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
main{max-width:760px;margin:20px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:14px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.06);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
button{padding:7px 12px;border:0;border-radius:8px;cursor:pointer;font-size:13px;color:#fff}
.runas{background:#7c3aed}.create{background:#16a34a}.logout{background:rgba(255,255,255,.2)}
input{padding:8px;border:1px solid #cbd5e1;border-radius:6px}.tag{font-size:12px;color:#64748b}
</style></head><body>
<header><h1 style=font-size:17px;margin:0>Vendor Admin</h1><div><a href="/vendor/admin/controls" style="color:#93c5fd;text-decoration:none;margin-right:14px;font-size:14px">⚙ Vendor controls</a><a href="/vendor/admin/orders" style="color:#93c5fd;text-decoration:none;margin-right:16px;font-size:14px">Orders dashboard</a><button class=logout onclick=logout()>Log out</button></div></header>
<main>
<div style="text-align:right;margin-bottom:12px"><button class=create onclick="toggleAdd()" id=addToggle>+ Add new vendor</button></div>
<div id=addForm style="display:none;background:#fff;border-radius:10px;padding:16px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.06)">
  <div style="font-weight:700;margin-bottom:10px">New vendor</div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center">
    <input id=nvName placeholder="Name">
    <input id=nvEmail placeholder="Email (required)">
    <input id=nvPhone placeholder="Phone (optional)">
    <label class=tag>Max digitizing <input id=nvMaxDig type=number min=0 value=3 style=width:55px></label>
    <label class=tag>Max other <input id=nvMaxOther type=number min=0 value=3 style=width:55px></label>
    <label class=tag>Idle limit (h) <input id=nvIdle type=number min=0 step=0.5 placeholder="default" style=width:60px></label>
    <label class=tag><input type=checkbox id=nvActive checked> Active</label>
  </div>
  <div class=tag style="margin:12px 0 6px">Capabilities</div>
  <div id=nvCaps style="display:flex;flex-wrap:wrap;gap:10px"></div>
  <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
    <input id=nvPw placeholder="Temp password (optional, 8+ to also create login)">
    <button class=create onclick="createVendor()">Create vendor</button>
    <span id=nvMsg class=tag></span>
  </div>
</div>
<div id=list></div></main><script>
const NVCAPS=['vector','separations','digitizing','ofm','pfx','digital_printing'];
const NVLABEL={digital_printing:'Digital (DTF/DTG)',separations:'\\u21b3 Separations (vector)',ofm:'\\u21b3 OFM (embroidery)',pfx:'\\u21b3 PXF (embroidery)'};
function toggleAdd(){
  const f=document.getElementById('addForm');
  const open=f.style.display==='none';
  f.style.display=open?'block':'none';
  document.getElementById('addToggle').textContent=open?'Close':'+ Add new vendor';
  if(open&&!document.getElementById('nvCaps').childElementCount){
    document.getElementById('nvCaps').innerHTML=NVCAPS.map(function(t){
      return '<label class=tag><input type=checkbox data-cap="'+t+'"> '+(NVLABEL[t]||t)+'</label>';
    }).join('');
    document.getElementById('nvCaps').addEventListener('change',function(e){
      if(!e.target.matches||!e.target.matches('input[type=checkbox][data-cap]'))return;
      var box=function(t){return document.querySelector('#nvCaps input[data-cap="'+t+'"]');};
      var tag=e.target.getAttribute('data-cap');
      if(e.target.checked){if(tag==='separations')box('vector').checked=true;if(tag==='ofm'||tag==='pfx')box('digitizing').checked=true;}
      else{if(tag==='vector')box('separations').checked=false;if(tag==='digitizing'){box('ofm').checked=false;box('pfx').checked=false;}}
    });
  }
}
async function createVendor(){
  const msg=document.getElementById('nvMsg');
  const email=document.getElementById('nvEmail').value.trim();
  if(!email){msg.textContent='Email required';msg.style.color='#dc2626';return;}
  const capabilities=[].slice.call(document.querySelectorAll('#nvCaps input[type=checkbox]')).filter(function(c){return c.checked;}).map(function(c){return c.getAttribute('data-cap');});
  const body={
    email:email,contact:document.getElementById('nvName').value.trim(),
    phone:document.getElementById('nvPhone').value.trim(),
    maxDigitizing:document.getElementById('nvMaxDig').value,
    maxOther:document.getElementById('nvMaxOther').value,
    active:document.getElementById('nvActive').checked,
    capabilities:capabilities,tempPassword:document.getElementById('nvPw').value.trim()
  };
  msg.textContent='Creating\u2026';msg.style.color='#64748b';
  try{
    const r=await fetch('/vendor/api/admin/create-vendor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){msg.textContent='Error: '+(d.error||'failed');msg.style.color='#dc2626';return;}
    msg.textContent='Vendor created'+(d.loginCreated?' with login':'')+' \u2713';msg.style.color='#16a34a';
    ['nvName','nvEmail','nvPhone','nvPw'].forEach(function(id){document.getElementById(id).value='';});
    document.querySelectorAll('#nvCaps input').forEach(function(c){c.checked=false;});
    load();
  }catch(e){msg.textContent='Error creating';msg.style.color='#dc2626';}
}
async function load(){
  const r=await fetch('/vendor/api/admin/vendors');const v=await r.json();
  list.innerHTML=v.map(x=>'<div class=card><div><b>'+x.name+'</b><div class=tag>'+x.email+'</div></div><div>'+
    (x.hasLogin?'':'<input id="p'+btoa(x.email)+'" placeholder="temp pw 8+"> <button class=create onclick="create(\\''+x.email+'\\')">Create login</button> ')+
    '<button class=runas onclick="runAs(\\''+x.email+'\\')">Run as</button></div></div>').join('');
}
async function create(email){
  const pw=document.getElementById('p'+btoa(email)).value;
  const r=await fetch('/vendor/api/admin/create-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,tempPassword:pw})});
  const d=await r.json();alert(d.ok?'Login created. Temp password: '+pw:d.error);load();
}
async function runAs(email){
  await fetch('/vendor/api/admin/run-as',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
  location.href='/vendor';
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
load();
</script></body></html>`;

module.exports = { mountVendorPortal };
