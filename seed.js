// Seed expenses.db with sample data (no real people or money). Remediated build.
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');               // FIX 8 - replaces unsalted MD5
const fs = require('fs');
const path = require('path');
const file = process.env.APP_DB || path.join(__dirname, 'expenses.db');
if (fs.existsSync(file)) fs.unlinkSync(file);
const db = new Database(file);
db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, name TEXT, role TEXT);
         CREATE TABLE claims (id INTEGER PRIMARY KEY, user_id INTEGER, merchant TEXT,
                              amount REAL, note TEXT, status TEXT, approver_id INTEGER);`);

// FIX 8 - bcrypt at cost 12. It's deliberately slow and salts each hash, so
// equal passwords don't share a hash and rainbow tables don't help.
const ROUNDS = 12;
[['jdoe','password1','Jane Doe','staff'],['rsmith','letmein','Rob Smith','staff'],
 ['achen','Summer2026','Ada Chen','finance'],['admin','admin','System Admin','admin']]
  .forEach(([u,p,n,r]) => db.prepare('INSERT INTO users (username,password,name,role) VALUES (?,?,?,?)')
    .run(u, bcrypt.hashSync(p, ROUNDS), n, r));

[[1,'Dublin Coach',24.5,'Client visit'],[1,'Aer Lingus',310,'Conference travel'],
 [2,'Tesco',18.2,'Team lunch'],[3,'Hotel Riu',480,'Offsite accommodation'],
 [4,'Amazon',129.99,'Spare laptop charger']]
  .forEach((c) => db.prepare("INSERT INTO claims (user_id,merchant,amount,note,status) VALUES (?,?,?,?,'pending')").run(...c));
fs.mkdirSync(path.join(__dirname, 'receipts'), { recursive: true });
for (let i = 1; i <= 5; i++)
  fs.writeFileSync(path.join(__dirname, 'receipts', `claim-${i}.txt`),
    `Meridian Expenses — receipt for claim ${i}\nSample data. Not a real receipt.\n`);
console.log('seeded:', file);
