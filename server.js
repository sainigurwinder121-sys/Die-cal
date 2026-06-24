const express = require('express');
const session = require('express-session');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const DB   = path.join(__dirname, 'data', 'keys.json');

// ── Admin password (change this to something secret) ──────────────────────────
const ADMIN_PASSWORD = 'admin@DieCalc2024';

// ── Helpers ───────────────────────────────────────────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB)) {
    fs.mkdirSync(path.dirname(DB), { recursive: true });
    fs.writeFileSync(DB, JSON.stringify({ keys: {} }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB, 'utf8'));
}
function saveDB(data) {
  fs.writeFileSync(DB, JSON.stringify(data, null, 2));
}
function hashFingerprint(fp) {
  return crypto.createHash('sha256').update(fp).digest('hex');
}
function generateKey(label) {
  const rand = crypto.randomBytes(6).toString('hex').toUpperCase();
  return `DK-${rand.slice(0,4)}-${rand.slice(4,8)}-${label.slice(0,3).toUpperCase()}`;
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'die-calc-secret-key-9182736',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 } // 8 hours
}));

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────

// POST /api/login  — accepts { key, fingerprint }
app.post('/api/login', (req, res) => {
  const { key, fingerprint } = req.body;
  if (!key || !fingerprint) return res.json({ ok: false, msg: 'Missing key or device info' });

  const db = loadDB();
  const entry = db.keys[key];

  if (!entry) return res.json({ ok: false, msg: 'Invalid access key' });
  if (!entry.active) return res.json({ ok: false, msg: 'This key has been revoked' });

  const fpHash = hashFingerprint(fingerprint);

  if (!entry.deviceHash) {
    // First use — bind this device
    db.keys[key].deviceHash   = fpHash;
    db.keys[key].firstUsed    = new Date().toISOString();
    db.keys[key].lastAccess   = new Date().toISOString();
    db.keys[key].accessCount  = 1;
    saveDB(db);
    req.session.authed = true;
    req.session.keyUsed = key;
    return res.json({ ok: true, msg: 'Welcome! Device registered.' });
  }

  if (entry.deviceHash !== fpHash) {
    // Different device — reject
    db.keys[key].rejectedAttempts = (db.keys[key].rejectedAttempts || 0) + 1;
    saveDB(db);
    return res.json({ ok: false, msg: 'This key is already bound to another device. Contact admin.' });
  }

  // Same device — allow
  db.keys[key].lastAccess  = new Date().toISOString();
  db.keys[key].accessCount = (db.keys[key].accessCount || 0) + 1;
  saveDB(db);
  req.session.authed  = true;
  req.session.keyUsed = key;
  return res.json({ ok: true, msg: 'Access granted' });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// GET /api/check  — check if session is valid
app.get('/api/check', (req, res) => {
  res.json({ authed: !!req.session.authed });
});

// ── ADMIN ROUTES (protected by admin password in session) ─────────────────────

app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  res.json({ ok: false, msg: 'Wrong admin password' });
});

function adminOnly(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).json({ ok: false, msg: 'Admin only' });
}

// GET /api/admin/keys — list all keys
app.get('/api/admin/keys', adminOnly, (req, res) => {
  const db = loadDB();
  res.json({ ok: true, keys: db.keys });
});

// POST /api/admin/create — create a new key
app.post('/api/admin/create', adminOnly, (req, res) => {
  const { label } = req.body;
  if (!label) return res.json({ ok: false, msg: 'Label required' });
  const db  = loadDB();
  const key = generateKey(label);
  db.keys[key] = {
    label,
    active:          true,
    deviceHash:      null,
    createdAt:       new Date().toISOString(),
    firstUsed:       null,
    lastAccess:      null,
    accessCount:     0,
    rejectedAttempts: 0
  };
  saveDB(db);
  res.json({ ok: true, key });
});

// POST /api/admin/revoke — revoke a key (disable but keep record)
app.post('/api/admin/revoke', adminOnly, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ ok: false, msg: 'Key not found' });
  db.keys[key].active = false;
  db.keys[key].revokedAt = new Date().toISOString();
  saveDB(db);
  res.json({ ok: true });
});

// POST /api/admin/reactivate — re-enable a key
app.post('/api/admin/reactivate', adminOnly, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ ok: false, msg: 'Key not found' });
  db.keys[key].active = true;
  db.keys[key].revokedAt = null;
  saveDB(db);
  res.json({ ok: true });
});

// POST /api/admin/unbind — remove device binding (so key can be used on new device)
app.post('/api/admin/unbind', adminOnly, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ ok: false, msg: 'Key not found' });
  db.keys[key].deviceHash = null;
  db.keys[key].firstUsed  = null;
  db.keys[key].accessCount = 0;
  saveDB(db);
  res.json({ ok: true });
});

// POST /api/admin/delete — permanently delete a key
app.post('/api/admin/delete', adminOnly, (req, res) => {
  const { key } = req.body;
  const db = loadDB();
  if (!db.keys[key]) return res.json({ ok: false, msg: 'Key not found' });
  delete db.keys[key];
  saveDB(db);
  res.json({ ok: true });
});

// ── PROTECTED APP ─────────────────────────────────────────────────────────────
function authOnly(req, res, next) {
  if (req.session.authed) return next();
  res.redirect('/');
}

app.get('/app', authOnly, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve login page and static files
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`\n✅ Die Calculator running on http://localhost:${PORT}`);
  console.log(`   App:   http://localhost:${PORT}/`);
  console.log(`   Admin: http://localhost:${PORT}/admin`);
  console.log(`   Admin password: ${ADMIN_PASSWORD}\n`);
});
