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
  // Fetch a Team's vendor-facing docs (templates + special instructions). FAIL-SAFE:
  // any error (Team not API-exposed, missing field, bad id) returns empty, never throws,
  // so the order card always renders even if the team lookup can't complete.
  async function teamDocs(teamId, cache) {
    if (!teamId) return { templates: [], instructions: "" };
    if (cache && cache.has(teamId)) return cache.get(teamId);
    const linkify = (val) => (!val ? null : (String(val).startsWith("//") ? "https:" + val : String(val)));
    let docs = { templates: [], instructions: "" };
    try {
      const t = await bubble("GET", `/team/${teamId}`).then(r => r.response);
      [["Template 1", t.Client_Template_1], ["Template 2", t.Client_Template_2], ["Template 3", t.Client_Template_3]]
        .forEach(([label, val]) => { const u = linkify(val); if (u) docs.templates.push({ label, url: u }); });
      docs.instructions = [t.Client_Special_Instructions_1, t.Client_Special_Instructions_2]
        .filter((s) => s && String(s).trim()).join("\n\n");
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
      specialInstructions: o.Special_Instructions || "",
      thumb,
      files: fileLinks(o),
      details: {
        ArtDims_Seps: o.ArtDims_Seps || "", FilmSizeSeps: o.FilmSizeSeps || "",
        ArtPlacement_Seps: o.ArtPlacement_Seps || "", Rush: o.Rush || "no",
        Unit: o.Unit || "", "cm/in": o["cm/in"] || "",
      },
    };
    if (team) v.team = team;
    return v;
  }

  app.get("/vendor/api/orders", requireVendor, async (req, res) => {
    try {
      const email = effectiveEmail(req.session);
      const a = await artistByEmail(email);
      const limit = a ? a.maxConcurrent : 0;
      const claimable = await search("uploaded_image", [
        { key: F.assignedArtist, constraint_type: "equals", value: email },
        { key: F.claimState, constraint_type: "equals", value: CS.unclaimed }]);
      const mine = await search("uploaded_image", [
        { key: F.assignedArtist, constraint_type: "equals", value: email },
        { key: F.claimState, constraint_type: "equals", value: CS.claimed }]);
      const teamCache = new Map();
      const claimedViews = await Promise.all(mine.map(async (o) =>
        orderView(o, await teamDocs(o.Team_Name, teamCache))));
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
      res.json({
        email, limit, openCount: load, claimedCount: mine.length, editCount, underLimit,
        actingAs: req.session.actingAs || null,
        edits: editViews,
        claimable: claimable.map((o) => orderView(o)),
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
      const orders = pending.map((o) => ({
        id: o._id, orderNo: o["Order#"] || "", type: o.Order_Type || "",
        user: o.User || "", assigned: String(o[F.assignedArtist] || ""),
        state: o[F.claimState] || "",
        ageHours: o["Created Date"] ? +(((now - new Date(o["Created Date"]).getTime()) / 3600000).toFixed(2)) : null,
        separations: o[F.separations] || "no", rush: o.Rush || "no",
      })).sort((a, b) => (b.ageHours || 0) - (a.ageHours || 0));
      const artistRows = artists.map((a) => ({
        email: String(a.email || "").toLowerCase(), contact: a.contact || "", active: a.is_active_vendor === true,
        cap: a.max_concurrent_orders, openEditsNow: editsByVendor[String(a.email || "").toLowerCase()] || 0,
        pending: a.pending_counter, aging: a.aging_counter,
        ordersToday: a.daily_counter, ordersMonth: a.monthly_counter,
        editsToday: a.edits_completed_today, editsMonth: a.monthly_edits,
        orderSpeedToday: a.daily_timer, orderSpeedMonth: a.monthly_timer, editSpeedMonth: a.monthly_edit_timer,
        editPctToday: a["Edit Percentage Today"], editPctMonth: a["Edit Percentage Month"],
      })).sort((x, y) => (x.email > y.email ? 1 : -1));
      const totals = {
        pending: pending.length,
        unassigned: pending.filter((o) => !o[F.assignedArtist]).length,
        openEdits: openEdits.length,
        vector: pending.filter((o) => o.Order_Type === "Vector").length,
        digitizing: pending.filter((o) => o.Order_Type === "Digitizing").length,
        digital: pending.filter((o) => o.Order_Type === "Digital (DTF/DTG)").length,
      };
      const vendors = artists.filter((a) => a.is_active_vendor === true)
        .map((a) => String(a.email || "").toLowerCase()).filter(Boolean).sort();
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
    rows+='<tr data-i="'+i+'"><td class=vh><div class=vemail>'+(v.email||'(no email)')+'</div><div class=vsub>'+(v.contact||'')+'</div></td>';
    columns.forEach(function(c){rows+='<td><input type=checkbox data-cap="'+c.tag+'" '+(caps.has(c.tag)?'checked':'')+'></td>';});
    rows+='<td><label class=switch><input type=checkbox class=active '+(v.active?'checked':'')+'><span class=slider></span></label></td>';
    rows+='<td><input type=number class=max min=0 value="'+((v.maxConcurrent===0||v.maxConcurrent)?v.maxConcurrent:'')+'"></td></tr>';
  });
  grid.innerHTML='<table>'+head+rows+'</table><div style=margin-top:14px><input id=newcap class=tagadd placeholder="add capability column"> <button class=addbtn onclick="addCol()">Add column</button> <span id=status class=saved></span></div>';
  grid.querySelector('table').addEventListener('change',function(e){const tr=e.target.closest('tr[data-i]');if(tr)saveRow(tr);});
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
body{font-family:system-ui,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
header{background:#0f172a;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
header a{color:#93c5fd;text-decoration:none;margin-left:14px;font-size:14px}
.wrap{max-width:1200px;margin:18px auto;padding:0 16px}
.totals{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.tcard{background:#fff;border-radius:10px;padding:12px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08);min-width:120px}
.tcard .n{font-size:22px;font-weight:800}.tcard .l{font-size:12px;color:#64748b}
.t-warn .n{color:#dc2626}
.sec{font-size:14px;color:#475569;font-weight:700;margin:18px 0 10px}
.statwrap{overflow-x:auto}
table.stats{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:13px}
table.stats th,table.stats td{padding:8px 10px;border-bottom:1px solid #eef2f6;text-align:center;white-space:nowrap}
table.stats th{background:#f1f5f9;color:#334155;font-weight:700}
table.stats td.vn,table.stats th.vn{text-align:left}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.on{background:#16a34a}.off{background:#cbd5e1}
.ocard{background:#fff;border-radius:10px;padding:14px;margin-bottom:10px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.ohead{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.ono{font-weight:700}.osub{color:#64748b;font-size:13px}
.age{font-weight:700;font-size:13px}.a-green{color:#16a34a}.a-orange{color:#d97706}.a-red{color:#dc2626}
.oact{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}
select,input{padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px}
button{border:0;border-radius:8px;padding:7px 12px;font-weight:600;cursor:pointer;font-size:13px}
.assign{background:#2563eb;color:#fff}.cancel{background:#fee2e2;color:#b91c1c}.logout{background:rgba(255,255,255,.2);color:#fff}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 7px;border-radius:999px;margin-left:6px}
.b-un{background:#fef3c7;color:#92400e}.b-rush{background:#fee2e2;color:#b91c1c}.b-sep{background:#e0e7ff;color:#3730a3}
.msg{font-size:12px;margin-left:6px}
</style></head><body>
<header><div><b>Orders Dashboard</b><a href="/vendor/admin">Vendor logins</a><a href="/vendor/admin/controls">Vendor controls</a></div>
<button class=logout onclick="logout()">Log out</button></header>
<div class=wrap>
<div id=totals class=totals></div>
<div class=sec>By vendor (stored metrics)</div><div class=statwrap><div id=stats></div></div>
<div class=sec>All pending orders <span id=ocount class=osub></span></div><div id=orders></div>
</div>
<script>
let DATA={vendors:[]};
function ageClass(h){if(h==null)return '';if(h>8)return 'a-red';if(h>=6)return 'a-orange';return 'a-green';}
async function load(){
  try{const r=await fetch('/vendor/api/admin/dashboard');DATA=await r.json();render();}
  catch(e){document.getElementById('orders').textContent='Failed to load dashboard.';}
}
function render(){
  const t=DATA.totals||{};
  document.getElementById('totals').innerHTML=
    tcard(t.pending,'Pending orders')+tcard(t.unassigned,'Unassigned',true)+tcard(t.openEdits,'Open edits')+
    tcard(t.vector,'Vector')+tcard(t.digitizing,'Digitizing')+tcard(t.digital,'Digital (DTF/DTG)');
  renderStats();renderOrders();
}
function tcard(n,l,warn){return '<div class="tcard'+(warn&&n?' t-warn':'')+'"><div class=n>'+(n==null?'0':n)+'</div><div class=l>'+l+'</div></div>';}
function renderStats(){
  const a=DATA.artists||[];
  if(!a.length){document.getElementById('stats').textContent='No vendors.';return;}
  const cols=[['pending','Orders Pending'],['openEditsNow','Open Edits (live)'],['aging','Aging'],
    ['orderSpeedToday','Order Spd Today'],['orderSpeedMonth','Order Spd Mo'],['editSpeedMonth','Edit Spd Mo'],
    ['editPctToday','Edit % Today'],['editPctMonth','Edit % Mo'],
    ['editsToday','Edits Fin Today'],['editsMonth','Edits Fin Mo'],['ordersToday','Ord Fin Today'],['ordersMonth','Ord Fin Mo'],['cap','Cap']];
  let h='<table class=stats><tr><th class=vn>Vendor</th>';cols.forEach(function(c){h+='<th>'+c[1]+'</th>';});h+='</tr>';
  a.forEach(function(v){
    h+='<tr><td class=vn><span class="dot '+(v.active?'on':'off')+'"></span>'+(v.contact||v.email||'(no email)')+'<div class=osub>'+(v.email||'')+'</div></td>';
    cols.forEach(function(c){var val=v[c[0]];h+='<td>'+(val==null||val===''?'–':val)+'</td>';});
    h+='</tr>';
  });
  h+='</table>';document.getElementById('stats').innerHTML=h;
}
function renderOrders(){
  const o=DATA.orders||[];
  document.getElementById('ocount').textContent='('+o.length+')';
  if(!o.length){document.getElementById('orders').innerHTML='<div class=osub>No pending orders.</div>';return;}
  const opts=(DATA.vendors||[]).map(function(e){return '<option value="'+e+'">'+e+'</option>';}).join('');
  document.getElementById('orders').innerHTML=o.map(function(x){
    const assigned=x.assigned?('Artist: '+x.assigned):'<span class="badge b-un">UNASSIGNED</span>';
    const badges=(x.rush==='yes'?'<span class="badge b-rush">RUSH</span>':'')+(x.separations==='yes'?'<span class="badge b-sep">SEPS</span>':'');
    const age=x.ageHours==null?'':'<span class="age '+ageClass(x.ageHours)+'">Age: '+x.ageHours+'h</span>';
    return '<div class=ocard data-id="'+x.id+'"><div class=ohead>'+
      '<div><div class=ono>Order # '+(x.orderNo||x.id)+' '+badges+'</div>'+
      '<div class=osub>'+(x.type||'')+' &middot; User: '+(x.user||'?')+'</div>'+
      '<div class=osub>'+assigned+'</div></div><div>'+age+'</div></div>'+
      '<div class=oact><select class=vsel>'+(x.assigned?'':'<option value="">choose vendor…</option>')+opts+'</select>'+
      '<button class=assign>'+(x.assigned?'Reassign':'Push')+'</button>'+
      '<button class=cancel>Cancel</button><span class=msg></span></div></div>';
  }).join('');
  // preselect current assignee
  o.forEach(function(x){if(x.assigned){const sel=document.querySelector('.ocard[data-id="'+x.id+'"] .vsel');if(sel)sel.value=x.assigned;}});
  document.getElementById('orders').addEventListener('click',onAction);
}
async function onAction(e){
  const card=e.target.closest('.ocard');if(!card)return;
  const id=card.getAttribute('data-id');const msg=card.querySelector('.msg');
  if(e.target.classList.contains('assign')){
    const email=card.querySelector('.vsel').value;
    if(!email){msg.textContent='Pick a vendor';msg.style.color='#dc2626';return;}
    msg.textContent='Assigning…';msg.style.color='#64748b';
    await post('/vendor/api/admin/assign-order',{id:id,email:email},msg,'Assigned ✓');
  }else if(e.target.classList.contains('cancel')){
    if(!confirm('Cancel this order? It will stop rotating and leave all queues.'))return;
    msg.textContent='Cancelling…';msg.style.color='#64748b';
    await post('/vendor/api/admin/cancel-order',{id:id},msg,'Cancelled ✓');
  }
}
async function post(url,body,msg,okText){
  try{
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j=await r.json();
    if(j.ok){msg.textContent=okText;msg.style.color='#16a34a';setTimeout(load,700);}
    else{msg.textContent='Error: '+(j.error||'failed');msg.style.color='#dc2626';}
  }catch(e){msg.textContent='Error';msg.style.color='#dc2626';}
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
load();
</script></body></html>`;

const PORTAL_HTML = `<!doctype html><html><head><meta charset=utf8><meta name=viewport content="width=device-width,initial-scale=1">
<title>My Orders</title><style>
body{font-family:system-ui,sans-serif;background:#f4f6fa;margin:0;color:#0f172a}
header{background:#2563eb;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:17px;margin:0}.banner{background:#f59e0b;color:#000;text-align:center;padding:8px;font-size:14px;font-weight:600}
main{max-width:900px;margin:20px auto;padding:0 16px}h2{font-size:15px;color:#475569;margin:24px 0 10px}
.card{background:#fff;border-radius:10px;padding:16px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.ref{font-weight:700;font-size:15px}.tag{font-size:12px;color:#64748b}
button{padding:8px 14px;border:0;border-radius:8px;cursor:pointer;font-size:14px}
.claim{background:#16a34a;color:#fff}.upload{background:#2563eb;color:#fff}.link{background:#e2e8f0;color:#0f172a;text-decoration:none;display:inline-block;margin:3px 4px 0 0;padding:6px 10px;border-radius:6px;font-size:13px}
.logout{background:rgba(255,255,255,.2);color:#fff}.details{font-size:13px;color:#475569;margin-top:8px;display:none}
.muted{color:#94a3b8;font-size:14px}.sep{color:#b45309;font-weight:600;font-size:12px}
.thumb{width:72px;height:72px;object-fit:cover;border-radius:8px;border:1px solid #e2e8f0;background:#fff;flex:none}
.cdetails{display:flex;gap:12px;margin-top:10px;align-items:flex-start}.cmeta{flex:1;min-width:0}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;margin:0 5px 5px 0;letter-spacing:.02em}
.b-type{background:#eef2ff;color:#3730a3}.b-rush{background:#fee2e2;color:#b91c1c}.b-sep{background:#fef3c7;color:#92400e}.b-edit{background:#fde68a;color:#92400e}
.timer{font-size:12px;margin:2px 0 4px;font-weight:600}.t-green{color:#16a34a}.t-orange{color:#d97706}.t-red{color:#dc2626;font-weight:700}
.notes{font-size:13px;color:#334155;background:#f8fafc;border-left:3px solid #cbd5e1;padding:6px 10px;border-radius:4px;margin-top:8px;white-space:pre-wrap}
.tmpl{margin-top:8px}.tmpl .link{background:#dbeafe;color:#1e40af}.tmpl-label{font-size:12px;color:#64748b;font-weight:700;margin-bottom:3px}
.editbox{margin-top:8px;padding:8px 10px;background:#fef2f2;border:1px solid #fecaca;border-radius:6px}.editbox .link{background:#fee2e2;color:#991b1b}
</style></head><body>
<div id=banner class=banner style=display:none></div>
<header><h1>PrintReadyArt — My Orders</h1><button class=logout onclick=logout()>Log out</button></header>
<main>
<div id=limit class=muted></div>
<div id=editsWrap style=display:none><h2 style="color:#b91c1c">⚑ Edit Requests</h2><div id=edits></div></div>
<h2>Available to Claim</h2><div id=claimable></div>
<h2>My Claimed Orders</h2><div id=claimed></div>
</main><script>
let data={};
async function load(){
  const r=await fetch('/vendor/api/orders');
  if(r.status===302||r.redirected){location.href='/vendor/login';return;}
  data=await r.json();
  if(data.actingAs){banner.style.display='block';banner.innerHTML='Viewing as '+data.actingAs+' — <a href="#" onclick="stopRunAs();return false">exit</a>';}
  limit.textContent='Limit: '+data.openCount+' / '+data.limit+(data.editCount?' ('+data.claimedCount+' claimed + '+data.editCount+' edit'+(data.editCount>1?'s':'')+')':'')+(data.underLimit?'':' — at limit, clear work to take more');
  claimable.innerHTML=data.claimable.length?data.claimable.map(card).join(''):'<div class=muted>Nothing to claim right now.</div>';
  claimed.innerHTML=data.claimed.length?data.claimed.map(c=>card(c,true)).join(''):'<div class=muted>No claimed orders.</div>';
  if(data.edits&&data.edits.length){editsWrap.style.display='block';edits.innerHTML=data.edits.map(c=>card(c,true,true)).join('');}
  else{editsWrap.style.display='none';edits.innerHTML='';}
}
function card(o,claimed,isEdit){
  const files=o.files.map(f=>'<a class=link target=_blank href="'+f.url+'">⬇ '+f.label+'</a>').join('');
  const sep=(!claimed&&o.separations==='yes')?'<span class=sep>SEPARATIONS</span> ':'';
  let action='';
  if(!claimed){action=data.underLimit?'<button class=claim onclick="claim(\\''+o.id+'\\')">Claim</button>':'<span class=tag>at limit</span>';}
  else if(isEdit&&!o.id){action='<span class=tag>original order not found</span>';}
  else{action='<button class=upload onclick="openUpload(\\''+o.id+'\\')">'+(isEdit?'Upload revised':'Upload completed')+'</button>';}
  let rich='';
  if(claimed){
    const badges=(isEdit?'<span class="badge b-edit">EDIT REQUEST</span>':'')+
      '<span class="badge b-type">'+esc(o.type||'—')+'</span>'+
      (o.rush==='yes'?'<span class="badge b-rush">RUSH</span>':'')+
      (o.separations==='yes'?'<span class="badge b-sep">SEPARATIONS</span>':'');
    const thumb=o.thumb?'<img class=thumb src="'+o.thumb+'" alt="artwork" onerror="this.style.display=\\'none\\'">':'';
    const tlabel=isEdit?'edit requested':'claimed';
    const tsince=(isEdit&&o.edit&&o.edit.created)?o.edit.created:o.claimedAt;
    const timer=tsince?'<div class="timer '+timerClass(tsince)+'" data-since="'+tsince+'" data-label="'+tlabel+'">\\u23F1 '+tlabel+' '+fmtElapsed(tsince)+' ago</div>':'';
    const notes=o.specialInstructions?'<div class=notes><b>Special instructions:</b> '+esc(o.specialInstructions)+'</div>':'';
    let tmpl='';
    if(o.team){
      const tl=(o.team.templates||[]).map(t=>'<a class=link target=_blank href="'+t.url+'">\\u2B07 '+esc(t.label)+'</a>').join('');
      const ti=o.team.instructions?'<div class=notes><b>Team instructions:</b> '+esc(o.team.instructions)+'</div>':'';
      if(tl||ti)tmpl='<div class=tmpl><div class=tmpl-label>Team templates &amp; instructions</div>'+tl+ti+'</div>';
    }
    // Edit-request detail block: notes, reason, and the client's reference files.
    let editBlock='';
    if(isEdit&&o.edit){
      const refLinks=(o.edit.refs||[]).map(rf=>'<a class=link target=_blank href="'+rf.url+'">\\u2B07 '+esc(rf.label)+'</a>').join('');
      editBlock='<div class=editbox>'+
        '<div class=tmpl-label style=color:#b91c1c>What the client wants changed</div>'+
        (o.edit.reason?'<div class=tag style=margin-bottom:4px>Reason: '+esc(o.edit.reason)+'</div>':'')+
        (o.edit.changes?'<div class=notes style=border-left-color:#dc2626>'+esc(o.edit.changes)+'</div>':'<div class=tag>(no note provided)</div>')+
        (refLinks?'<div style=margin-top:6px><div class=tmpl-label>Reference files</div>'+refLinks+'</div>':'')+
        '</div>';
    }
    const orig=isEdit?'<div class=tmpl-label style=margin-top:8px>Original work</div>':'';
    rich='<div class=cdetails>'+thumb+'<div class=cmeta>'+badges+timer+notes+tmpl+editBlock+'</div></div>'+orig;
  }
  let uploadBox='';
  if(claimed){
    const emb=(o.type||'').toLowerCase()==='digitizing';
    const embFields=emb?(
      '<div class=tag style=margin-top:8px;color:#b45309;font-weight:600>Digitizing — required:</div>'+
      '<input id=w'+o.id+' type=number placeholder="Width" style=width:90px>'+
      '<input id=h'+o.id+' type=number placeholder="Height" style=width:90px>'+
      '<input id=sc'+o.id+' type=number placeholder="Stitch count" style=width:120px>'
    ):'';
    uploadBox='<div id=up'+o.id+' class=uploadbox style="display:none;margin-top:10px;padding:10px;background:#f8fafc;border-radius:8px">'+
      '<div class=tag>Preview JPEG (before/after) → Image:</div>'+
      '<input id=prev'+o.id+' type=file accept="image/*">'+
      '<div class=tag style=margin-top:8px>Supporting files (replaces existing):</div>'+
      '<input id=sup'+o.id+' type=file multiple>'+
      embFields+
      '<div class=tag style=margin-top:8px>Number of logos in order (required):</div>'+
      '<input id=lg'+o.id+' type=number placeholder="# of logos" style=width:120px>'+
      '<div style=margin-top:10px><button class=upload onclick="submitUpload(\\''+o.id+'\\','+emb+')">Submit & mark complete</button></div>'+
      '</div>';
  }
  const title=o.ref||('Order '+o.orderNo);
  const subline=o.ref?('Order '+o.orderNo+' · '+o.type):o.type;
  return '<div class=card><div class=row><div><span class=ref>'+title+'</span> '+sep+
    '<div class=tag>'+subline+'</div></div><div>'+action+'</div></div>'+
    rich+
    (claimed?('<div style=margin-top:10px>'+files+'</div>'+uploadBox):'')+
    '</div>';
}
function esc(s){return String(s==null?'':s).replace(/[<>&]/g,function(c){return c==='<'?'&lt;':c==='>'?'&gt;':'&amp;';});}
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
  if(h>8)return 't-red';
  if(h>=6)return 't-orange';
  return 't-green';
}
function openUpload(id){const b=document.getElementById('up'+id);b.style.display=b.style.display==='none'?'block':'none';}
async function claim(id){
  const r=await fetch('/vendor/api/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({orderId:id})});
  const d=await r.json();
  if(!d.ok){alert(d.reason||d.error||'Could not claim');}
  load();
}
async function submitUpload(id,emb){
  const prev=document.getElementById('prev'+id).files[0];
  const sup=document.getElementById('sup'+id).files;
  if(!prev && sup.length===0){alert('Attach a preview or at least one file');return;}
  const logos=document.getElementById('lg'+id).value;
  if(!logos){alert('Number of logos is required');return;}
  const fd=new FormData();fd.append('orderId',id);fd.append('logos',logos);
  if(prev)fd.append('preview',prev);
  for(const f of sup)fd.append('supporting',f);
  if(emb){
    const h=document.getElementById('h'+id).value,w=document.getElementById('w'+id).value,sc=document.getElementById('sc'+id).value;
    if(!h||!w||!sc){alert('Digitizing orders require Width, Height, and Stitch Count');return;}
    fd.append('height',h);fd.append('width',w);fd.append('stitchCount',sc);
  }
  const r=await fetch('/vendor/api/upload',{method:'POST',body:fd});
  const d=await r.json();
  if(!d.ok){alert(d.error||'Upload failed');}else{alert('Uploaded — order marked complete.');}
  load();
}
async function logout(){await fetch('/vendor/api/logout',{method:'POST'});location.href='/vendor/login';}
async function stopRunAs(){await fetch('/vendor/api/admin/stop-run-as',{method:'POST'});location.href='/vendor/admin';}
function anyUploadOpen(){return [...document.querySelectorAll('.uploadbox')].some(el=>el.style.display==='block');}
setInterval(function(){
  document.querySelectorAll('.timer[data-since]').forEach(function(el){
    var s=el.getAttribute('data-since'),lbl=el.getAttribute('data-label')||'claimed';
    el.className='timer '+timerClass(s);
    el.textContent='\\u23F1 '+lbl+' '+fmtElapsed(s)+' ago';
  });
},1000);
load();
setInterval(()=>{if(!anyUploadOpen())load();},30000);
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
const NVLABEL={digital_printing:'Digital (DTF/DTG)'};
function toggleAdd(){
  const f=document.getElementById('addForm');
  const open=f.style.display==='none';
  f.style.display=open?'block':'none';
  document.getElementById('addToggle').textContent=open?'Close':'+ Add new vendor';
  if(open&&!document.getElementById('nvCaps').childElementCount){
    document.getElementById('nvCaps').innerHTML=NVCAPS.map(function(t){
      return '<label class=tag><input type=checkbox data-cap="'+t+'"> '+(NVLABEL[t]||t)+'</label>';
    }).join('');
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
