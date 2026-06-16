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
    push("Optimized", o.Optimized_Image);
    if (Array.isArray(o.Supporting_Files)) o.Supporting_Files.forEach((f, i) => push(`Supporting ${i + 1}`, f));
    return out;
  }
  function orderView(o) {
    return {
      id: o._id,
      ref: o[REF_FIELD] || o._id,
      orderNo: o["Order#"] || "",
      type: o.Order_Type || "",
      user: o.User || "",
      state: o[F.claimState] || "",
      claimDeadline: o[F.claimDeadline] || null,
      separations: o[F.separations] || "no",
      files: fileLinks(o),
      details: {
        ArtDims_Seps: o.ArtDims_Seps || "", FilmSizeSeps: o.FilmSizeSeps || "",
        ArtPlacement_Seps: o.ArtPlacement_Seps || "", Rush: o.Rush || "no",
        Unit: o.Unit || "", "cm/in": o["cm/in"] || "",
      },
    };
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
      const underLimit = mine.length < limit;
      res.json({
        email, limit, openCount: mine.length, underLimit,
        actingAs: req.session.actingAs || null,
        claimable: claimable.map(orderView),
        claimed: mine.map(orderView),
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

  // ---- UPLOAD COMPLETED WORK  (real fields: Image + Supporting_Files) ------
  // Preview JPEG -> Image ; other files -> appended to Supporting_Files list ;
  // Pending -> no. Uses Bubble's /fileupload to store bytes, gets URLs back.
  async function uploadToBubble(filename, buffer) {
    const fileEndpoint = BUBBLE_BASE.replace(/\/obj\/?$/, "") + "/fileupload";
    const res = await fetch(fileEndpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${BUBBLE_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: filename, contents: buffer.toString("base64") }),
    });
    if (!res.ok) throw new Error(`Bubble fileupload (${filename}) -> ${res.status} ${await res.text()}`);
    let url = (await res.text()).trim().replace(/^"|"$/g, "");
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

      // Verify this order is actually claimed by this vendor.
      const o = await getOrder(orderId);
      if (!o) return res.status(404).json({ ok: false, error: "Order not found" });
      if (o[F.assignedArtist] !== email) return res.status(403).json({ ok: false, error: "Not your order" });
      if (o[F.claimState] !== CS.claimed) return res.status(400).json({ ok: false, error: "Order is not in your claimed list" });

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
        Artist_reported_count: Number(logos),
      };

      if (isEmbroidery) {
        patch.Height = Number(height);
        patch.Width = Number(width);
        patch.Stitch_Count = Number(stitch);
      }

      // Preview JPEG -> Image field
      if (previewFile) {
        patch.Image = await uploadToBubble(previewFile.originalname, previewFile.buffer);
      }

      // Supporting files -> OVERRIDE Supporting_Files (replace whatever's there).
      if (supportFiles.length) {
        const urls = [];
        for (const f of supportFiles) urls.push(await uploadToBubble(f.originalname, f.buffer));
        patch.Supporting_Files = urls;
      }

      await patchOrder(orderId, patch);
      await logEvent(orderId, email, "completed_uploaded",
        `${previewFile ? "preview" : "no preview"}; ${supportFiles.length} supporting file(s)`);
      res.json({ ok: true, preview: !!previewFile, supporting: supportFiles.length });
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

  // ---- PAGES (served HTML) -------------------------------------------------
  app.get("/vendor/login", (_req, res) => res.type("html").send(LOGIN_HTML));
  app.get("/vendor", requireVendor, (_req, res) => res.type("html").send(PORTAL_HTML));
  app.get("/vendor/admin", requireAdminLogin, (_req, res) => res.type("html").send(ADMIN_HTML));
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
</style></head><body>
<div id=banner class=banner style=display:none></div>
<header><h1>PrintReadyArt — My Orders</h1><button class=logout onclick=logout()>Log out</button></header>
<main>
<div id=limit class=muted></div>
<h2>Available to Claim</h2><div id=claimable></div>
<h2>My Claimed Orders</h2><div id=claimed></div>
</main><script>
let data={};
async function load(){
  const r=await fetch('/vendor/api/orders');
  if(r.status===302||r.redirected){location.href='/vendor/login';return;}
  data=await r.json();
  if(data.actingAs){banner.style.display='block';banner.innerHTML='Viewing as '+data.actingAs+' — <a href="#" onclick="stopRunAs();return false">exit</a>';}
  limit.textContent='Limit: '+data.openCount+' / '+data.limit+' claimed'+(data.underLimit?'':' — at limit, finish work to claim more');
  claimable.innerHTML=data.claimable.length?data.claimable.map(card).join(''):'<div class=muted>Nothing to claim right now.</div>';
  claimed.innerHTML=data.claimed.length?data.claimed.map(c=>card(c,true)).join(''):'<div class=muted>No claimed orders.</div>';
}
function card(o,claimed){
  const files=o.files.map(f=>'<a class=link target=_blank href="'+f.url+'">⬇ '+f.label+'</a>').join('');
  const sep=o.separations==='yes'?'<span class=sep>SEPARATIONS</span> ':'';
  let action='';
  if(!claimed){action=data.underLimit?'<button class=claim onclick="claim(\\''+o.id+'\\')">Claim</button>':'<span class=tag>at limit</span>';}
  else{action='<button class=upload onclick="openUpload(\\''+o.id+'\\')">Upload completed</button>';}
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
  return '<div class=card><div class=row><div><span class=ref>'+o.ref+'</span> '+sep+
    '<div class=tag>Order '+o.orderNo+' · '+o.type+'</div></div><div>'+action+'</div></div>'+
    (claimed?('<div style=margin-top:10px>'+files+'</div>'+uploadBox):'')+
    '</div>';
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
<header><h1 style=font-size:17px;margin:0>Vendor Admin</h1><button class=logout onclick=logout()>Log out</button></header>
<main><div id=list></div></main><script>
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
