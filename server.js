// Meridian Expenses - fixed build (CA1). The FIX n tags line up with the
// finding numbers in the report.
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');                     // FIX 8 - pure JS, no build step on Windows
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();
// APP_DB lets the tests point at a throwaway database (CA2)
const DB_PATH = process.env.APP_DB || path.join(__dirname, 'expenses.db');
const db = new Database(DB_PATH);

// FIX 7 - secret from the env, and don't start without it
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET missing or too short. Set a 32+ char secret and restart.');
  process.exit(1);
}
const PROD = process.env.NODE_ENV === 'production';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

function currentUser(req) {
  const t = req.cookies.token;
  if (!t) return null;
  try {
    return jwt.verify(t, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    return null;
  }
}

// FIX 4/5 - auth + role in one place so no route forgets them
function requireAuth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.redirect('/login');
  req.user = u;
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).send('Forbidden');
    next();
  };
}

app.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM claims WHERE user_id = ? ORDER BY id DESC').all(req.user.uid);  // FIX 1 - bound
  res.render('index', { claims: rows, user: req.user });
});

app.get('/login', (req, res) => res.render('login', { error: req.query.e || null }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare('SELECT id, name, role, password FROM users WHERE username = ?').get(username || '');  // FIX 1
  // FIX 8 / CWE-204 - same message + a dummy compare either way, so we don't
  // give away which usernames exist
  const hash = row ? row.password : '$2b$12$0000000000000000000000000000000000000000000000000000';
  const ok = bcrypt.compareSync(password || '', hash);
  if (!row || !ok) return res.redirect('/login?e=' + encodeURIComponent('Invalid username or password.'));

  const token = jwt.sign({ uid: row.id, name: row.name, role: row.role },
                         JWT_SECRET, { algorithm: 'HS256', expiresIn: '2h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: PROD, maxAge: 2 * 60 * 60 * 1000 });  // FIX 11
  res.redirect('/');
});

app.get('/logout', (req, res) => { res.clearCookie('token'); res.redirect('/login'); });

app.get('/claim/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM claims WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send('Not found');
  // FIX 4 - own claim only (finance/admin can see all). a valid id isn't enough
  // on its own now, which is the IDOR gone
  if (row.user_id !== req.user.uid && !['finance', 'admin'].includes(req.user.role)) {
    return res.status(403).send('Forbidden');
  }
  res.render('claim', { c: row, user: req.user });
});

app.post('/claim/new', requireAuth, (req, res) => {
  db.prepare(`INSERT INTO claims (user_id, merchant, amount, note, status)
              VALUES (?,?,?,?,'pending')`)
    .run(req.user.uid, req.body.merchant, req.body.amount, req.body.note);
  res.redirect('/');
});

// Claim approval workflow (CA2). Only finance or admin may approve, and the
// business rule is that nobody approves their own claim (self-approval, CWE-841).
app.post('/claim/:id/approve', requireAuth, requireRole('finance', 'admin'), (req, res) => {
  const row = db.prepare('SELECT * FROM claims WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send('Not found');
  if (row.user_id === req.user.uid) {
    return res.status(403).send('You cannot approve your own claim');   // CWE-841 - no self-approval
  }
  if (row.status !== 'pending') return res.status(409).send('Claim is not pending');
  db.prepare("UPDATE claims SET status = 'approved', approver_id = ? WHERE id = ?")
    .run(req.user.uid, req.params.id);
  res.redirect('/claim/' + req.params.id);
});

app.get('/receipt', requireAuth, (req, res) => {
  const f = req.query.f || '';
  // FIX 3 - allow-list the name, then resolve and make sure it's still inside
  // receipts/ before sending. containment, not stripping ".."
  if (!/^claim-\d+\.txt$/.test(f)) return res.status(400).send('Invalid receipt name');
  const base = path.join(__dirname, 'receipts');
  const target = path.resolve(base, f);
  if (target !== path.join(base, f) || !target.startsWith(base + path.sep)) {
    return res.status(400).send('Invalid path');
  }
  res.sendFile(target);
});

app.get('/export', requireAuth,  (req, res) => {
  const month = req.query.month || '2026-09';
  // FIX 2 - no shell. validate the month, read with a prepared stmt, build the
  // csv here, so there's no command to break out of
  if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).send('Invalid month');
  const rows = db.prepare('SELECT id, user_id, merchant, amount, note, status FROM claims').all();
  // csv quoting + formula-injection guard (CWE-1236): prefix a leading = + - @
  // so a spreadsheet shows it as text
  const esc = (v) => {
    let s = String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return `"${s.replace(/"/g, '""')}"`;
  };
  const header = 'id,user_id,merchant,amount,note,status';
  const body = rows.map((r) => [r.id, r.user_id, r.merchant, r.amount, r.note, r.status].map(esc).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="expenses-${month}.csv"`);
  res.send(header + '\n' + body + '\n');
});

app.post('/profile', requireAuth, (req, res) => {
  // FIX 9 - name only, and bound. stops someone adding role=admin to the form
  const name = (req.body.name || '').toString().slice(0, 100);
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.user.uid);
  res.redirect('/');
});

app.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  const rows = db.prepare('SELECT id, username, name, role FROM users').all();
  res.render('admin', { users: rows });
});

app.get('/go', (req, res) => {
  // FIX 10 - relative same-site paths only. reject //host and /\host too, since
  // the browser reads the backslash as a slash and would leave the site
  const next = (req.query.next || '/').toString();
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\')) {
    return res.redirect('/');
  }
  res.redirect(next);
});

// FIX 7 - /debug/config is gone. the old hard-coded key is treated as
// compromised and rotated; we run on a fresh env secret now.

// FIX 7 - don't leak stack traces to the client
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Internal Server Error');
});

// Start a server only when run directly; the tests import the app with supertest (CA2)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '127.0.0.1', () =>
    console.log(`Meridian Expenses on http://127.0.0.1:${PORT}`));
}

module.exports = app;
