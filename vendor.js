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
      ref: o[REF_FIELD] || "",
      orderNo: o["Order#"] || "",
      type: o.Order_Type || "",
      user: o.User || "",
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
      const rows = await search("new_orders", [{ key: "Order#", constraint_type: "equals", value: orderNo }]);
      const n = rows[0];
      if (!n) return null;
      return {
        puff: n["3D_Puff"] === true ? "Yes" : (n["3D_Puff"] === false ? "No" : ""),
        fabric: n.fabric_content || "",
        placement: n.Placement || "",
      };
    } catch (e) { console.warn("[orders] new_orders lookup failed for " + orderNo + ":", e.message); return null; }
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
      const done = await search("uploaded_image", [
        { key: F.assignedArtist, constraint_type: "equals", value: email },
        { key: F.claimState, constraint_type: "equals", value: "completed" },
        { key: "Modified Date", constraint_type: "greater than", value: monIso }]);
      ordersMonth = done.length; let s = 0, n = 0;
      done.forEach((o) => { if (o.claimed_at && o["Modified Date"]) { const h = (new Date(o["Modified Date"]).getTime() - new Date(o.claimed_at).getTime()) / 3600000; if (h >= 0) { s += h; n++; } } });
      orderSpeed = n ? +(s / n).toFixed(1) : null;
    } catch (e) { console.warn("[orders] monthly order speed failed:", e.message); }
    try {
      const em = await search("edit_request", [
        { key: "Assigned_Artist", constraint_type: "equals", value: email },
        { key: "Completed", constraint_type: "greater than", value: monIso }]);
      editsMonth = em.length; let s = 0, n = 0;
      em.forEach((e) => { if (e["Created Date"] && e.Completed) { const h = (new Date(e.Completed).getTime() - new Date(e["Created Date"]).getTime()) / 3600000; if (h >= 0) { s += h; n++; } } });
      editSpeed = n ? +(s / n).toFixed(1) : null;
    } catch (e) { console.warn("[orders] monthly edit speed failed:", e.message); }
    const out = { at: Date.now(), orderSpeed, editSpeed, ordersMonth, editsMonth };
    _speedCache.set(email, out);
    return out;
  }

  // Send the "your order is ready" email to the client. Best-effort: any failure is
  // logged and swallowed so a mail hiccup never blocks order completion.
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
      // Cap load = claimed work + open edits (matches the engine's countClaimed). Open
      // edits consume slots so a vendor can't take new work until edits are cleared.
      const editCount = openEdits.length;
      const load = mine.length + editCount;
      const underLimit = load < limit;
      const editViews = await Promise.all(openEdits.map(async (er) => {
        let order = null;
        try {
          const m = await search("uploaded_image", [{ key: "Order#", constraint_type: "equals", value: er["Order#"] }]);
          order = m[0] || null;
        } catch (e) { console.warn("[orders] order lookup failed for " + er["Order#"] + ":", e.message); }
        const base = order
          ? orderView(order, await teamDocs(order.Team_Name, teamCache))
          : { id: null, ref: "", orderNo: er["Order#"] || "", type: er.Order_Type || "", thumb: "", files: [], separations: "no", rush: "no", specialInstructions: "" };
        base.id = order ? order._id : null; // "Upload revised" must target the ORDER
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
        email, limit, openCount: load, claimedCount: mine.length, editCount, underLimit,
        actingAs: req.session.actingAs || null,
        monthlyTimer: sp.orderSpeed, monthlyEditTimer: sp.editSpeed,
        monthlyCount: sp.ordersMonth, monthlyEdits: sp.editsMonth,
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

      const patch = {
        Pending: false, Edit_Requested: false, [F.claimState]: "completed",
        artist_reported_count: Number(logos),
      };

      if (isEmbroidery) {
        patch.Height = Number(height);
        patch.Width = Number(width);
        patch.Stitch_Count = Number(stitch);
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

      // Client "your order is ready" email. Fires on BOTH triggers: original order
      // completion and edit-request completion. The original completion sends once per
      // order (guarded by message_sent) so a re-upload won't double-send; an edit
      // completion is its own client-facing event and always sends.
      if (isEditSubmit) {
        await sendCompletionEmail(o);
      } else if (String(o.message_sent || "").toLowerCase() !== "yes") {
        await sendCompletionEmail(o);
        try { await patchOrder(orderId, { message_sent: "yes" }); }
        catch (e) { console.warn("[email] message_sent flag write failed:", e.message); }
      }

      await logEvent(orderId, email, isEditSubmit ? "edit_revised" : "completed_uploaded",
        `${previewFile ? "preview" : "no preview"}; ${supportFiles.length} supporting file(s)`);
      res.json({ ok: true, edit: isEditSubmit, preview: !!previewFile, supporting: supportFiles.length });
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
      if (req.body.maxConcurrent !== undefined && req.body.maxConcurrent !== "" && req.body.maxConcurrent !== null)
        rec.max_concurrent_orders = Number(req.body.maxConcurrent);
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
        maxConcurrent: (a.max_concurrent_orders === 0 || a.max_concurrent_orders) ? a.max_concurrent_orders : "",
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
      if (req.body.maxConcurrent !== undefined && req.body.maxConcurrent !== "" && req.body.maxConcurrent !== null)
        patch.max_concurrent_orders = Number(req.body.maxConcurrent);
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
      const [artists, pending, openEdits] = await Promise.all([
        search("artist", []),
        search("uploaded_image", [{ key: "Pending", constraint_type: "equals", value: true }]),
        search("edit_request", [{ key: "Completed", constraint_type: "is_empty" }]),
      ]);
      const now = Date.now();
      const editsByVendor = {};
      openEdits.forEach((e) => { const a = String(e.Assigned_Artist || "").toLowerCase(); if (a) editsByVendor[a] = (editsByVendor[a] || 0) + 1; });
      // An order is only ACTUALLY claimed when claim_state === "claimed". The engine
      // pre-stamps nothing now (shared pool), but legacy rows may still carry a stamp;
      // claim_state is the only source of truth for "claimed".
      const isClaimed = (o) => (o[F.claimState] || "") === "claimed";
      const orders = pending.map((o) => {
        const created = o["Created Date"] ? (now - new Date(o["Created Date"]).getTime()) / 3600000 : null;
        const claimed = (isClaimed(o) && o.claimed_at) ? (now - new Date(o.claimed_at).getTime()) / 3600000 : null;
        return {
          id: o._id, orderNo: o["Order#"] || "", ref: o["Customer_PO#"] || "", type: o.Order_Type || "",
          user: o.User || "", state: o[F.claimState] || "",
          assigned: isClaimed(o) ? String(o[F.assignedArtist] || "") : "",
          reqCaps: requiredCapsFor(o),
          thumb: o.image ? (String(o.image).startsWith("//") ? "https:" + o.image : String(o.image)) : "",
          createdHours: created != null ? +created.toFixed(2) : null,
          claimedHours: claimed != null ? +claimed.toFixed(2) : null,
          separations: o[F.separations] || "no", rush: o.Rush || "no",
          multiEdit: o["Multiple Edit Alert"] === true,
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
        aging: pending.filter((o) => { const h = hSinceClaim(o); return h != null && h > 8; }).length,
        multiEdit: pending.filter((o) => o["Multiple Edit Alert"] === true).length,
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
        if (!byV[email]) byV[email] = { op: 0, ag: 0, ep: 0, ot: 0, om: 0, et: 0, em: 0, osT: [0, 0], osM: [0, 0], esM: [0, 0] };
        return byV[email];
      };
      const orderSpeedH = (o) => { if (!o.claimed_at || !o["Modified Date"]) return null; const h = (new Date(o["Modified Date"]).getTime() - new Date(o.claimed_at).getTime()) / 3600000; return h >= 0 ? h : null; };
      const editSpeedH = (e) => { if (!e["Created Date"] || !e.Completed) return null; const h = (new Date(e.Completed).getTime() - new Date(e["Created Date"]).getTime()) / 3600000; return h >= 0 ? h : null; };
      pending.forEach((o) => { if (!isClaimed(o)) return; const b = bucket(o[F.assignedArtist]); if (!b) return; b.op++; const h = hSinceClaim(o); if (h != null && h > 8) b.ag++; });
      openEdits.forEach((e) => { const b = bucket(e.Assigned_Artist); if (b) b.ep++; });
      try {
        const done = await search("uploaded_image", [
          { key: F.claimState, constraint_type: "equals", value: "completed" },
          { key: "Modified Date", constraint_type: "greater than", value: iso }]);
        totals.completedToday = done.length;
        done.forEach((o) => { const b = bucket(o[F.assignedArtist]); if (!b) return; b.ot++; const h = orderSpeedH(o); if (h != null) { b.osT[0] += h; b.osT[1]++; } });
      } catch (e) { console.warn("[dashboard] completedToday failed:", e.message); totals.completedToday = null; }
      try {
        const mo = await search("uploaded_image", [
          { key: F.claimState, constraint_type: "equals", value: "completed" },
          { key: "Modified Date", constraint_type: "greater than", value: monIso }]);
        totals.completedMonth = mo.length;
        mo.forEach((o) => { const b = bucket(o[F.assignedArtist]); if (!b) return; b.om++; const h = orderSpeedH(o); if (h != null) { b.osM[0] += h; b.osM[1]++; } });
      } catch (e) { console.warn("[dashboard] completedMonth failed:", e.message); totals.completedMonth = null; }
      try {
        const et = await search("edit_request", [{ key: "Completed", constraint_type: "greater than", value: iso }]);
        totals.editsToday = et.length;
        et.forEach((e) => { const b = bucket(e.Assigned_Artist); if (b) b.et++; });
      } catch (e) { console.warn("[dashboard] editsToday failed:", e.message); totals.editsToday = null; }
      try {
        const em = await search("edit_request", [{ key: "Completed", constraint_type: "greater than", value: monIso }]);
        totals.editsMonth = em.length;
        em.forEach((e) => { const b = bucket(e.Assigned_Artist); if (!b) return; b.em++; const h = editSpeedH(e); if (h != null) { b.esM[0] += h; b.esM[1]++; } });
      } catch (e) { console.warn("[dashboard] editsMonth failed:", e.message); totals.editsMonth = null; }

      const avg = (pair) => (pair && pair[1]) ? +(pair[0] / pair[1]).toFixed(2) : null;
      const artistRows = artists.map((a) => {
        const em = String(a.email || "").toLowerCase(); const b = byV[em] || {};
        const om = b.om || 0, emc = b.em || 0;
        return {
          email: em, contact: a.contact || "", active: a.is_active_vendor === true, cap: a.max_concurrent_orders,
          capabilities: Array.isArray(a.capabilities) ? a.capabilities.map((c) => String(c).toLowerCase()) : [],
          ordersPending: b.op || 0, editsPending: b.ep || 0, aging: b.ag || 0,
          orderSpeedToday: avg(b.osT), orderSpeedMonth: avg(b.osM), editSpeedMonth: avg(b.esM),
          editPctMonth: om ? +((emc / om) * 100).toFixed(1) : null,
          editsToday: b.et || 0, editsMonth: emc, ordersToday: b.ot || 0, ordersMonth: om,
        };
      }).sort((x, y) => (x.email > y.email ? 1 : -1));
      const vendors = artists.filter((a) => a.is_active_vendor === true)
        .map((a) => String(a.email || "").toLowerCase()).filter(Boolean).sort();
      // Unread indicator: vendor messages the admin hasn't read (one cheap search).
      try {
        const unread = await search(OM, [
          { key: "sender_role", constraint_type: "equals", value: "vendor" },
          { key: "read_by_admin", constraint_type: "equals", value: false }]);
        const unreadSet = new Set(unread.map((m) => String(m.order_no)));
        orders.forEach((o) => { if (unreadSet.has(String(o.orderNo))) o.unread = true; });
      } catch (e) { console.warn("[dashboard] unread scan failed:", e.message); }
      res.json({ totals, artists: artistRows, orders, vendors });
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
  app.get("/vendor/api/admin/raw", requireAdminLogin, async (req, res) => {
    try {
      const type = String(req.query.type || "uploaded_image");
      const id = String(req.query.id || "");
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
  head+='<th>Active</th><th>Max</th></tr>';
  let rows='';
  vendors.forEach(function(v,i){
    const caps=new Set((v.capabilities||[]).map(function(c){return String(c).toLowerCase();}));
    // An active vendor can't actually receive work if they have no email (system finds
    // vendors only by email), no capabilities, or a zero/blank max. Flag it loudly.
    var maxv=v.maxConcurrent;var maxOk=(maxv!==''&&maxv!=null&&Number(maxv)>0);
    var problems=[];
    if(v.active&&!(v.email&&String(v.email).trim()))problems.push('no email \\u2014 cannot be found');
    if(v.active&&caps.size===0)problems.push('no capabilities');
    if(v.active&&!maxOk)problems.push('max is 0/blank');
    var warn=problems.length?' warnrow':'';
    rows+='<tr data-i="'+i+'" class="'+warn.trim()+'"><td class=vh><div class=vemail>'+(v.email||'<span class=nomail>(no email)</span>')+'</div><div class=vsub>'+(v.contact||'')+'</div>'+
      (problems.length?'<div class=warnmsg>\\u26A0 Active but can\\'t claim: '+problems.join('; ')+'</div>':'')+'</td>';
    columns.forEach(function(c){rows+='<td><input type=checkbox data-cap="'+c.tag+'" '+(caps.has(c.tag)?'checked':'')+'></td>';});
    rows+='<td><label class=switch><input type=checkbox class=active '+(v.active?'checked':'')+'><span class=slider></span></label></td>';
    rows+='<td><input type=number class=max min=0 value="'+((v.maxConcurrent===0||v.maxConcurrent)?v.maxConcurrent:'')+'"></td></tr>';
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
  const maxv=tr.querySelector('.max').value;
  const status=document.getElementById('status');status.textContent='Saving\u2026';status.style.color='#64748b';
  try{
    const r=await fetch('/vendor/api/admin/vendor-controls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:v.id,capabilities:capabilities,maxConcurrent:maxv,active:active})});
    const j=await r.json();
    v.capabilities=capabilities;v.active=active;v.maxConcurrent=maxv;
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
  <div class=toppanels><div id=totalPanel class=totalpanel></div><div id=tiles class=tiles></div></div>
  <div class=toolbar>
    <label>Sort <select id=sortSel onchange="setSort(this.value)">
      <option value=placed>Time since placed</option><option value=held>Time held (claimed)</option><option value=vendor>Vendor</option><option value=type>Type</option><option value=multi>Multiple edits first</option></select></label>
    <label>Vendor <select id=fVendor onchange="setFilter()"><option value="">All</option></select></label>
    <label>State <select id=fState onchange="setFilter()"><option value="">All</option><option value=unassigned>Unassigned</option><option value=assigned>Assigned</option></select></label>
    <label>Type <select id=fType onchange="setFilter()"><option value="">All</option></select></label>
    <label><input type=checkbox id=fMulti onchange="setFilter()"> Multiple edits only</label>
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
let sortBy='placed',fltVendor='',fltState='',fltType='',fltMulti=false;
function fmtH(h){if(h==null)return '\\u2013';if(h>=48)return (h/24).toFixed(1)+'d';return h+'h';}
function ageClass(h){if(h==null)return 't-green';if(h>8)return 't-red';if(h>=6)return 't-orange';return 't-green';}
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
  populateFilters();renderTotals();renderTiles();renderList();renderStats();
  if(panelOpenId&&byId[panelOpenId])fillPanel(byId[panelOpenId]);
}
function renderTotals(){
  var t=DATA.totals||{};var v=function(n){return n==null?'0':n;};
  document.getElementById('totalPanel').innerHTML='<h3>Total</h3>'+
    '<div class=r>Pending Orders: <span>'+v(t.pending)+'</span></div>'+
    '<div class="r tp-red">Aging Orders: <span>'+v(t.aging)+'</span></div>'+
    '<div class=r>Edits Pending: <span>'+v(t.openEdits)+'</span></div>'+
    '<div class="r tp-orange tp-click" onclick="filterMulti()">Multiple Edit Alerts: <span>'+v(t.multiEdit)+'</span></div>'+
    '<div class=r>Edits Completed Today: <span>'+v(t.editsToday)+'</span></div>'+
    '<div class=r>Orders Completed Today: <span>'+v(t.completedToday)+'</span></div>'+
    '<div class=r>Orders Completed This Month: <span>'+v(t.completedMonth)+'</span></div>';
}
function renderTiles(){
  var t=DATA.totals||{};function tile(n,l,w){return '<div class="tile'+(w&&n?' warn':'')+'"><div class=n>'+(n==null?'0':n)+'</div><div class=l>'+l+'</div></div>';}
  var un=(DATA.orders||[]).filter(function(o){return !o.assigned;});
  var oldest=0;un.forEach(function(o){if(o.createdHours!=null&&o.createdHours>oldest)oldest=o.createdHours;});
  var oldestTile='<div class="tile'+(un.length?' warn':'')+'"><div class=n>'+(un.length?fmtH(oldest):'\\u2013')+'</div><div class=l>Oldest unclaimed</div></div>';
  document.getElementById('tiles').innerHTML=tile(t.unassigned,'Unassigned',true)+oldestTile+tile(t.vector,'Vector')+tile(t.digitizing,'Digitizing')+tile(t.digital,'Digital (DTF/DTG)')+tile(t.other,'Other / unknown',true);
}
function populateFilters(){
  var vsel=document.getElementById('fVendor');var cur=vsel.value;
  var vs=(DATA.vendors||[]).slice();(DATA.orders||[]).forEach(function(o){if(o.assigned&&vs.indexOf(o.assigned)<0)vs.push(o.assigned);});
  vsel.innerHTML='<option value="">All</option>'+vs.map(function(e){return '<option value="'+e+'">'+esc(shortUser(e))+'</option>';}).join('');vsel.value=cur;
  var tsel=document.getElementById('fType');var curt=tsel.value;var types=[];
  (DATA.orders||[]).forEach(function(o){var tp=o.type||'(none)';if(types.indexOf(tp)<0)types.push(tp);});
  tsel.innerHTML='<option value="">All</option>'+types.map(function(tp){return '<option value="'+esc(tp)+'">'+esc(tp)+'</option>';}).join('');tsel.value=curt;
}
function setSort(v){sortBy=v;renderList();}
function setFilter(){fltVendor=document.getElementById('fVendor').value;fltState=document.getElementById('fState').value;fltType=document.getElementById('fType').value;fltMulti=document.getElementById('fMulti').checked;renderList();}
function filterMulti(){document.getElementById('fMulti').checked=true;showTab('orders');setFilter();}
function applyFilter(arr){return arr.filter(function(o){
  if(fltVendor&&o.assigned!==fltVendor)return false;
  if(fltState==='unassigned'&&o.assigned)return false;
  if(fltState==='assigned'&&!o.assigned)return false;
  if(fltType&&(o.type||'(none)')!==fltType)return false;
  if(fltMulti&&!o.multiEdit)return false;
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
  var marks=(o.unread?'<span class="mini msgnew">\\uD83D\\uDCAC New</span>':'')+(o.separations==='yes'?'<span class="mini m-sep">Sep</span>':'')+(o.rush==='yes'?'<span class="mini m-rush">Rush</span>':'')+(o.multiEdit?'<span class="mini m-multi">\\u26A0 Multi-edit</span>':'');
  var pill=(o.claimedHours!=null)
    ? '<div class="timer '+ageClass(o.claimedHours)+'" title="Time held since claimed">'+fmtH(o.claimedHours)+'</div>'
    : '<div class="timer '+ageClass(o.createdHours)+'" title="Unclaimed \\u2014 time since placed">\\u231B '+fmtH(o.createdHours)+'</div>';
  return '<div class="row'+(o.multiEdit?' multi':'')+'" onclick="openDetail(\\''+o.id+'\\')">'+thumb+
    '<div class=rmain><div class=rtitle>Order '+esc(o.orderNo||o.id)+marks+'</div><div class=rsub>'+esc(o.type||'(no type)')+' \\u00b7 '+esc(shortUser(o.user||'?'))+'</div></div>'+
    '<div class=rasg>'+assigned+'</div><div class=rright>'+pill+'<i class=chev>\\u203A</i></div></div>';
}
function renderStats(){
  var a=DATA.artists||[];if(!a.length){document.getElementById('stats').textContent='No vendors.';return;}
  var cols=[['ordersPending','Orders Pending'],['editsPending','Edits Pending'],['aging','Aging Orders'],
    ['orderSpeedToday','Order Speed Today','spd'],['orderSpeedMonth','Order Speed Month','spd'],['editSpeedMonth','Edit Speed Month','spd'],
    ['editPctMonth','Edit % Month','pct'],['editsToday','Edits Finished Today'],['editsMonth','Edits Finished Month'],['ordersToday','Orders Finished Today'],['ordersMonth','Orders Finished Month']];
  var h='<table class=stats><tr><th class=vn>By Artist</th>';cols.forEach(function(c){h+='<th>'+c[1]+'</th>';});h+='</tr>';
  a.forEach(function(v){h+='<tr><td class=vn><span class="dot '+(v.active?'on':'off')+'"></span>'+esc(v.contact||v.email||'(no email)')+'<div class=osub>'+esc(v.email||'')+'</div></td>';
    cols.forEach(function(c){var val=v[c[0]];var cls=c[2]==='spd'?spdClass(val):(c[2]==='pct'?pctClass(val):'');var disp=(val==null||val==='')?'\\u2013':(c[2]==='pct'?val+'%':val);h+='<td class="'+cls+'">'+disp+'</td>';});h+='</tr>';});
  h+='</table>';document.getElementById('stats').innerHTML=h;
}
function eligibleFor(o){
  var req=o.reqCaps||[];
  return (DATA.artists||[]).filter(function(a){
    if(!a.active)return false;
    var caps=(a.capabilities||[]).map(function(c){return String(c).toLowerCase();});
    for(var i=0;i<req.length;i++){if(caps.indexOf(req[i])<0)return false;}
    return true;
  }).map(function(a){
    var load=(a.ordersPending||0)+(a.editsPending||0);
    var cap=(a.cap==null||a.cap==='')?null:Number(a.cap);
    return {email:a.email,contact:a.contact,load:load,cap:cap,under:(cap==null||load<cap)};
  });
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
  panel.innerHTML='<div class=phead><div><div class=ptitle>Order '+esc(o.orderNo||o.id)+'</div><div class=peyebrow>'+esc(o.type||'')+(o.ref?' \\u00b7 PO '+esc(o.ref):'')+'</div></div><button class=pclose onclick="closeDetail()">\\u2715</button></div>'+
    '<div class=pbody>'+multi+'<div>'+badges+'</div>'+thumb+
    '<div class=specline><b>Client:</b> '+esc(o.user||'?')+'</div>'+statusBlock+
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
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
load();
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
  var slots=(data.openCount!=null?data.openCount:0)+' of '+(data.limit!=null?data.limit:0);
  var full=!data.underLimit;
  var mt=(data.monthlyTimer!=null&&data.monthlyTimer!=='')?(data.monthlyTimer+'h'):'\\u2013';
  var met=(data.monthlyEditTimer!=null&&data.monthlyEditTimer!=='')?(data.monthlyEditTimer+'h'):'\\u2013';
  chips.innerHTML=
    (ed?'<span class="chip danger">'+ed+' edit'+(ed===1?'':'s')+'</span>':'')+
    (av?'<span class="chip info">'+av+' ready to claim</span>':'')+
    '<span class=chip title="Avg turnaround this month \\u2014 orders (claim\\u2192done) / edits">Month \\u23F1 '+esc(String(mt))+' ord / '+esc(String(met))+' edit</span>'+
    '<span class="chip slots'+(full?' full':'')+'">'+slots+' slots</span>'+
    '<button class=logout onclick=logout()>Log out</button>';
}
function renderList(){
  var av=(data.claimable||[]).slice(),pr=(data.claimed||[]).slice(),ed=(data.edits||[]).slice();
  pr.sort(function(a,b){return new Date(a.claimedAt||0)-new Date(b.claimedAt||0);});
  ed.sort(function(a,b){var m=(b.multiEdit?1:0)-(a.multiEdit?1:0);if(m)return m;return new Date((a.edit&&a.edit.created)||0)-new Date((b.edit&&b.edit.created)||0);});
  var html=groupHtml('Edit requests',ed,'edit')+groupHtml('Available to claim',av,'available')+groupHtml('In progress',pr,'progress');
  main.innerHTML=html||'<div class=muted>Nothing in your queue right now.</div>';
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
    var act=data.underLimit?'<button class=claim onclick="claim(\\''+o.id+'\\')">Claim</button>':'<span style=color:#94a3b8;font-size:13px>At limit</span>';
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
  var sub=(state==='edit')?esc((o.edit&&o.edit.changes)||'Edit requested'):('Order '+esc(o.orderNo)+(o.user?' \\u00b7 '+esc(shortUser(o.user)):''));
  var since=(state==='edit'&&o.edit)?o.edit.created:o.claimedAt;var lbl=state==='edit'?'edit requested':'claimed';
  var right=since?'<div class="timer '+timerClass(since)+'" data-since="'+since+'" data-label="'+lbl+'">'+elapsedText(lbl,since)+'</div>':'';
  return '<div class="'+cls+'" onclick="openDetail(\\''+o._key+'\\')">'+thumb+
    '<div class=rmain><div class=rtitle>'+esc(o.ref||('Order '+o.orderNo))+marks+'</div><div class=rsub>'+sub+'</div></div>'+
    '<div class=rtype>'+esc(o.type||'')+'</div><div class=rright>'+right+'<i class=chev>\\u203A</i></div></div>';
}
function specBlockHtml(o){
  var d=o.details||{};var unit=d['cm/in']||d.Unit||'';var out='';
  function rowS(label,val){return (val===''||val==null)?'':'<div class=specline><b>'+label+':</b> '+esc(String(val))+'</div>';}
  if(o.separations==='yes'){var sb=rowS('Film Size',d.FilmSizeSeps)+rowS('Art Size',d.ArtDims_Seps)+rowS('Art Placement',d.ArtPlacement_Seps)+rowS('Unit',unit);if(sb)out+='<div class=spec><div class=spec-label>Separations spec</div>'+sb+'</div>';}
  if((o.type||'').toLowerCase()==='digitizing'){var no=d.newOrder||{};var db=rowS('Height',d.Height)+rowS('Width',d.Width)+rowS('Unit',unit)+rowS('3D Puff',no.puff)+rowS('Fabric content',no.fabric)+rowS('Placement',no.placement);if(db)out+='<div class=spec><div class=spec-label>Digitizing spec</div>'+db+'</div>';}
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
  panel.innerHTML='<div class=phead><div><div class=ptitle>'+esc(o.ref||('Order '+o.orderNo))+'</div><div class=peyebrow>Order '+esc(o.orderNo||'')+(o.type?' \\u00b7 '+esc(o.type):'')+'</div></div><div style=display:flex;gap:8px;align-items:center>'+pill+'<button class=pclose onclick="closeDetail()">\\u2715</button></div></div>'+
    '<div class=pbody>'+multi+'<div>'+badges+'</div>'+thumb+(state==='edit'?editBlockHtml(o):'')+notes+specBlockHtml(o)+tmplBlockHtml(o)+filesBlockHtml(o,state)+action+(state!=='available'?msgBlockHtml(o):'')+'</div>';
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
  if(h>8)return 't-red';if(h>=6)return 't-orange';return 't-green';
}
async function claim(id){
  const r=await fetch('/vendor/api/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id})});
  const d=await r.json();
  if(!d.ok){var m=d.reason==='claim_oldest_first'?'Please claim the oldest order in line first.':(d.reason==='at_limit_finish_open_work_first'?'You\\'re at your limit \\u2014 finish open work first.':(d.reason||d.error||'Could not claim'));alert(m);}
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
    <label class=tag>Max concurrent <input id=nvMax type=number min=0 value=3 style=width:60px></label>
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
    maxConcurrent:document.getElementById('nvMax').value,
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
